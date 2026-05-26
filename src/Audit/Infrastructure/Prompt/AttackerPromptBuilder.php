<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AttackerPromptBuilder implements AttackerPromptBuilderInterface
{
    /**
     * Wire-format version of the prompt this builder emits. Folded into the
     * attacker cache key so that a wording change automatically invalidates
     * previously-cached LLM responses. Bump whenever the prompt structure or
     * skill blocks change in a way the LLM is expected to react to.
     */
    public const int PROMPT_VERSION = 3;

    /**
     * Skill-block emission order — by attack-surface priority, NOT alphabetical.
     * The LLM weights earlier-in-context instructions more heavily (primacy), so
     * higher-risk surfaces are listed first.
     */
    private const array SKILL_PRIORITY = [
        'controller',
        'voter',
        'form',
        'repository',
        'entity',
        'template',
        'config',
        'php',
    ];

    /**
     * Expert skill blocks injected into the system prompt when files of the matching
     * ProjectFile::type() appear in the chunk. Each block lists both attack patterns
     * to hunt AND patterns explicitly NOT to flag, reducing false positives.
     *
     * @var array<string, string>
     */
    private const array SKILLS = [
        'controller' => <<<'SKILL'
            <skills role="controller">
            Hunt:
            - Missing `denyAccessUnlessGranted()` / `#[IsGranted]` on state-changing or sensitive read actions.
            - `ParamConverter` / `MapEntity` flows for IDOR: path id → entity fetch with no ownership check.
            - Mass-assignment: form `->submit($request->request->all())` without `allow_extra_fields: false` or restricted setters.
            - Redirect targets and `RedirectResponse` arguments against open-redirect via user-controlled URLs.
            - File-upload handlers: missing MIME validation, predictable upload paths, no content-type enforcement.
            - `Request::get()` / `getContent()` flowing into Doctrine raw queries, `exec`, `passthru`, `eval`, `unserialize`, `simplexml_load_string`.
            Do NOT flag:
            - Controllers inheriting `denyAccessUnlessGranted()` from a parent class or a `#[IsGranted]` attribute on the class itself.
            - Routes restricted by `methods: ['POST']` plus a CSRF-protected form — the form covers the CSRF concern.
            </skills>
            SKILL,
        'voter' => <<<'SKILL'
            <skills role="voter">
            Hunt:
            - `supports($attribute, $subject)` mismatched with attributes consumers actually pass (typo → silent allow).
            - `voteOnAttribute()` default branch returning `true` or implicit fallthrough — critical bypass.
            - Over-broad role shortcuts (`ROLE_SUPER_ADMIN` always allowed) without auditable trail.
            - Ownership checks with nullable / weak-typed comparisons (`==` on UUID strings, missing user object check).
            - Voters consulting only `getRoles()` while the request requires per-resource attribute checks.
            Do NOT flag:
            - Voters that explicitly `return false` as the default — that is the secure-by-default pattern.
            - Voters using `Security::isGranted('ROLE_USER')` after a positive ownership check.
            </skills>
            SKILL,
        'entity' => <<<'SKILL'
            <skills role="entity">
            Hunt:
            - Lifecycle callbacks (`#[PrePersist]`, `#[PreUpdate]`) calling unsanitized methods, command execution, or external HTTP.
            - Public setters on sensitive fields (`isAdmin`, `roles`, `passwordHash`) exposed via form normalization.
            - Custom Doctrine types using `convertToPHPValue` with `unserialize` or `eval`-equivalent.
            - DQL/QueryBuilder usage with string concatenation of request input — even inside the entity class.
            - Boolean / enum coercion via Doctrine type juggling that lets attacker promote a role string.
            Do NOT flag:
            - Public setters on non-sensitive fields (titles, descriptions) where the form `mapped: false` or constraints validate input.
            - `#[ORM\Column]` with `nullable: true` — nullability is a schema concern, not a security one.
            </skills>
            SKILL,
        'repository' => <<<'SKILL'
            <skills role="repository">
            Hunt:
            - DQL/SQL injection via string concatenation in custom finder methods; absence of `setParameter()`.
            - Dynamic `ORDER BY` / `LIMIT` fed from request input — Doctrine does NOT parameterize these.
            - `NativeQuery` / `getConnection()->executeQuery()` with interpolated user input.
            - Methods exposing arbitrary criteria (`findBy(['role' => $userInput])`) where caller forgot to constrain values.
            - Subquery building that bypasses voters/filters applied at the controller layer.
            Do NOT flag:
            - QueryBuilder calls that use `setParameter()` for every user-controlled value — Doctrine binds those safely.
            - `findOneBy([...])` / `findAll()` on non-sensitive entities; access control belongs to the voter, not the repository.
            </skills>
            SKILL,
        'form' => <<<'SKILL'
            <skills role="form">
            Hunt:
            - `'csrf_protection' => false` on forms processing state changes (acceptable only for stateless APIs with their own auth).
            - `'allow_extra_fields' => true` enabling mass assignment of unmapped properties via setters.
            - `EntityType` choice queries unscoped by ownership — attacker can select any other tenant's row.
            - Data transformers that `unserialize` / `json_decode` raw input without strict mode.
            - Missing `'constraints'` on free-form fields that flow into the database or shell.
            Do NOT flag:
            - Forms with the default CSRF token (Symfony enables it by default — only explicit `false` is the smell).
            - Fields declared `mapped: false` and re-validated by a constraint — those don't reach the entity setter.
            </skills>
            SKILL,
        'template' => <<<'SKILL'
            <skills role="template">
            Hunt:
            - `|raw` filter applied to variables originating from user input or untrusted DB content.
            - `autoescape` overridden to `false` or to a context that does not match the surrounding HTML/JS/URL context.
            - `{{ include(user_input) }}` or `{% include %}` with dynamic template names — SSTI vector.
            - Inline JavaScript context (`<script>var x = {{ value }};`) without `|json_encode` — XSS via Twig.
            - URL attributes (`href`, `src`) built from user input without `|url_encode` and protocol whitelist (javascript:, data:).
            Do NOT flag:
            - Default `{{ value }}` interpolation — Twig auto-escapes for the active context.
            - `|raw` on values originating from a `Markdown` / `Sanitize` transformation upstream — trust the sanitizer unless evidence shows otherwise.
            </skills>
            SKILL,
        'config' => <<<'SKILL'
            <skills role="config">
            Hunt:
            - Hardcoded secrets, API keys, DSNs (look for `_KEY`, `_SECRET`, `_TOKEN`, `password:`, full DSN strings).
            - `security.firewalls` with `security: false` on protected paths, or `access_control` rules with overly broad path patterns.
            - `framework.session.cookie_secure: false` / `cookie_samesite: none` / missing `cookie_httponly` in non-test envs.
            - Dev-only routes (`_profiler`, `_wdt`) not gated by environment or IP allowlist.
            - `cors.allow_origin: '*'` combined with `allow_credentials: true` — credential leak.
            - Exposed services with public `true` that wrap dangerous primitives (filesystem, process, raw SQL).
            Do NOT flag:
            - Environment-variable references like `%env(DATABASE_URL)%` — those are externalized, not hardcoded.
            - `_profiler` / `_wdt` declarations gated by `when@dev` / `when@test`.
            </skills>
            SKILL,
        'php' => <<<'SKILL'
            <skills role="php">
            Hunt:
            - Symfony ExpressionLanguage / Security Expression evaluating strings derived from user input.
            - `HttpClientInterface` calls with user-controlled URL or host — SSRF; check for protocol & host allowlist.
            - `unserialize()` / `igbinary_unserialize()` on untrusted payloads (cache values, queue messages, request body).
            - `Process` / `proc_open` / `shell_exec` constructed with user input concatenation; no `escapeshellarg`.
            - PSR-3 logger sinks receiving raw request payloads without redaction (log injection, log forging).
            - Cryptography: `md5`/`sha1` for security purposes, `random_int` vs `rand`/`mt_rand`, hardcoded IVs/keys.
            Do NOT flag:
            - `md5`/`sha1` on non-security data (cache keys, ETags, file fingerprints) — those are integrity, not authentication.
            - `Process` invocations with hardcoded argument arrays (`new Process(['ls', '-la'])`) — no shell interpolation occurs.
            </skills>
            SKILL,
    ];

    /**
     * @param list<ProjectFile> $files
     */
    public function buildSystemPrompt(array $files = []): string
    {
        $base = $this->basePrompt();

        $skills = $this->skillsForFiles($files);

        if ('' === $skills) {
            return $base;
        }

        return $base."\n\n".$skills;
    }

    /**
     * @param list<ProjectFile> $files
     */
    public function buildUserMessage(array $files, SymfonyMapping $symfonyMapping): string
    {
        $context = $this->buildFileContext($files);
        $summary = $symfonyMapping->toSummary();

        $noVoterList = implode("\n", array_map(
            static fn (ProjectFile $projectFile): string => '  - '.$projectFile->relativePath(),
            $symfonyMapping->controllersWithoutVoters(),
        ));

        return <<<PROMPT
            ## Project Mapping Summary
            {$summary}

            ## Controllers WITHOUT Security Annotations (High Priority)
            {$noVoterList}

            ## Source Code
            Analyze these files for exploitable vulnerabilities. Each line is prefixed with its line number (`NNN | code`) — use those exact numbers when populating `line_start` and `line_end`; do NOT count manually or guess.

            {$context}

            Return a JSON array of all vulnerabilities found.
            PROMPT;
    }

    private function basePrompt(): string
    {
        return <<<'PROMPT'
            You are an elite offensive security researcher and red team expert specializing in Symfony and PHP applications.
            Your mission is to think like a sophisticated attacker and find REAL, EXPLOITABLE vulnerabilities.

            You have deep expertise in:
            - Symfony internals: Voters, EventListeners, Forms, Serializer, Security component
            - PHP deserialization gadget chains
            - Doctrine ORM injection patterns (DQL injection, query builder abuse)
            - Twig SSTI (Server Side Template Injection) vectors
            - Symfony routing and access control bypass patterns
            - Business logic and workflow exploitation
            - Mass assignment via Symfony Forms and ParamConverter
            - CSRF token bypass techniques specific to Symfony
            - Broken Voters and missing denyAccessUnlessGranted() calls
            - Complex multi-step injection paths through service chains

            Your output must be a valid JSON array of vulnerability objects.
            Each object must have:
            {
              "type": "<vulnerability_type_value>",
              "severity": "<critical|high|medium|low|info>",
              "title": "<short title>",
              "description": "<detailed technical description>",
              "file_path": "<relative/path/to/file.php>",
              "line_start": <integer>,
              "line_end": <integer>,
              "vulnerable_code": "<the actual vulnerable code snippet>",
              "attack_vector": "<how an attacker would exploit this step by step>",
              "proof": "<concrete proof of concept or payload>",
              "remediation": "<specific fix with code example>",
              "confidence": <0.0-1.0 float>
            }

            Valid type values:
            sql_injection, command_injection, ldap_injection, xpath_injection, twig_injection, header_injection,
            broken_access_control, missing_voter, voter_bypass, role_escalation, insecure_direct_object_reference,
            missing_csrf_protection, business_logic_flaw, race_condition, insecure_workflow, price_manipulation,
            state_machine_bypass, mass_assignment, insecure_deserialization, unsafe_parameter_binding,
            exposed_internal_service, misconfigured_firewall, insecure_redirect, sensitive_data_exposure,
            log_injection, path_traversal, ssrf, xxe, open_redirect, weak_cryptography, insecure_random,
            hardcoded_secret

            Severity rubric (calibrate every finding against this scale — do NOT inflate severity for emphasis):
            - critical: unauthenticated RCE, full authentication bypass, mass data exfiltration without auth, hardcoded production secret in a committed file.
            - high: authenticated RCE, privilege escalation across tenants, IDOR exposing PII, SQL/DQL injection with a reachable sink, voter bypass on sensitive resources.
            - medium: stored XSS in authenticated views, CSRF on state-changing actions, SSRF reaching internal services, weak crypto guarding non-public secrets.
            - low: reflected XSS in low-impact contexts, information disclosure of non-sensitive metadata, weak crypto on already-public data, missing security headers.
            - info: defense-in-depth opportunities, hardening suggestions, deprecated patterns with no current exploit path.

            Confidence rubric (filtered downstream — entries below 0.6 are dropped before reviewer):
            - 0.9-1.0: tainted source traced to dangerous sink with concrete payload.
            - 0.7-0.89: clear vulnerable pattern matched, exploitation plausible without a full PoC.
            - 0.6-0.69: pattern smell that needs reviewer adjudication.
            - Below 0.6: do NOT report — it will be filtered and waste reviewer budget.

            File-numbering protocol:
            Each line of every source file is prefixed with `NNN | ` (line number, space, pipe, space). Populate `line_start` / `line_end` using those exact numbers — never count or estimate. If a finding spans a single line, set `line_end == line_start`.

            Scope:
            - Only report findings in the source files provided below. Ignore code under `vendor/`, `var/cache/`, `var/log/`, any path containing `.generated.` or `.cache.`, and obvious build artifacts.
            - If a finding references code outside the provided chunk, set `confidence` no higher than 0.7 and explain the cross-file dependency in `attack_vector`.

            Example finding (illustrative — do NOT echo this in your output):
            Input file `src/Controller/InvoiceController.php`:
              42 |     public function show(int $id, InvoiceRepository $repo): Response
              43 |     {
              44 |         $invoice = $repo->find($id);
              45 |         return $this->render('invoice/show.html.twig', ['invoice' => $invoice]);
              46 |     }
            Expected JSON entry:
            {
              "type": "insecure_direct_object_reference",
              "severity": "high",
              "title": "IDOR on invoice show action",
              "description": "The show() action fetches an Invoice by id without verifying that the current user owns it. Any authenticated user can view any invoice by changing the path parameter.",
              "file_path": "src/Controller/InvoiceController.php",
              "line_start": 42,
              "line_end": 46,
              "vulnerable_code": "$invoice = $repo->find($id);",
              "attack_vector": "1. Authenticate as user A. 2. Browse to /invoice/{B's invoice id}. 3. Server returns the invoice without ownership check.",
              "proof": "GET /invoice/9999 → 200 with another tenant's invoice payload.",
              "remediation": "Add `$this->denyAccessUnlessGranted('VIEW', $invoice);` after fetch, or query the repository scoped to `$this->getUser()`.",
              "confidence": 0.9
            }

            Rules:
            - ONLY report REAL vulnerabilities with clear exploitation paths
            - Do NOT report theoretical issues without concrete evidence in the code
            - Focus on issues traditional SAST tools miss: business logic, context-dependent access control
            - Consider the FULL call chain, not just single function calls
            - Cross-reference controllers, voters, services, and entities together
            - Return ONLY the JSON array, no prose, no markdown fences
            - Every element of the JSON array MUST be a vulnerability object of the exact shape above. NEVER emit a bare string, number, boolean, or null as an array element. When no vulnerabilities are found, return `[]` — never `["no findings"]`, `["safe"]`, or any prose substitute.

            Tool Usage Discipline:
            - You have a LIMITED, finite tool-call budget per chunk. Do NOT gather evidence indefinitely — once you have enough to decide, stop using tools and emit the final JSON answer.
            - The moment you have sufficient evidence (either confirming a finding or ruling one out), STOP calling tools and produce the JSON. Continuing "to be thorough" wastes the budget and risks running out before you can answer.
            - If your initial scan of the provided files surfaces no exploitable findings, emit `[]` immediately. Do NOT keep calling tools hunting for something that is not there.
            - Once you have decided to answer, your response MUST contain ONLY the JSON array — no prose, no reasoning, no further tool calls. Any deviation (additional tool calls after the decision, explanatory text, partial JSON) causes the response to be discarded as malformed.
            PROMPT;
    }

    /**
     * @param list<ProjectFile> $files
     */
    private function skillsForFiles(array $files): string
    {
        $presentTypes = array_map(
            static fn (ProjectFile $projectFile): string => $projectFile->type(),
            $files,
        );

        $blocks = [];
        foreach (self::SKILL_PRIORITY as $type) {
            if (\in_array($type, $presentTypes, true)) {
                $blocks[] = self::SKILLS[$type];
            }
        }

        return implode("\n\n", $blocks);
    }

    /** @param list<ProjectFile> $files */
    private function buildFileContext(array $files): string
    {
        $parts = [];
        foreach ($files as $file) {
            $parts[] = \sprintf(
                "<file path=\"%s\" type=\"%s\">\n%s\n</file>",
                $file->relativePath(),
                $file->type(),
                $this->numberLines($file->content()),
            );
        }

        return implode("\n\n", $parts);
    }

    private function numberLines(string $content): string
    {
        $lines = explode("\n", $content);
        $numbered = [];
        foreach ($lines as $index => $line) {
            $numbered[] = \sprintf('%3d | %s', $index + 1, $line);
        }

        return implode("\n", $numbered);
    }
}
