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
     * Expert skill blocks injected into the system prompt when files of the matching
     * ProjectFile::type() appear in the chunk. Each block is a focused, technical
     * checklist of attack patterns specific to that artifact type. Keep them tight —
     * the LLM rewards precision over volume.
     *
     * @var array<string, string>
     */
    private const array SKILLS = [
        'controller' => <<<'SKILL'
            ### Controller Specialist Skills
            - Hunt for missing `denyAccessUnlessGranted()` / `#[IsGranted]` on state-changing or sensitive read actions.
            - Inspect `ParamConverter` / `MapEntity` flows for IDOR: path id → entity fetch with no ownership check.
            - Flag mass-assignment risks: form `->submit($request->request->all())` without `allow_extra_fields: false` controls or restricted setters.
            - Check redirect targets and `RedirectResponse` arguments against open-redirect via user-controlled URLs.
            - Inspect file-upload handlers: missing MIME validation, predictable upload paths, no content-type enforcement.
            - Look for `Request::get()` / `getContent()` flowing into Doctrine raw queries, `exec`, `passthru`, `eval`, `unserialize`, `simplexml_load_string`.
            SKILL,
        'voter' => <<<'SKILL'
            ### Voter Specialist Skills
            - Verify `supports($attribute, $subject)` matches the attributes consumers actually pass (typo → silent allow).
            - Check `voteOnAttribute()` default branch: returning `true` or implicit fallthrough is a critical bypass.
            - Hunt for over-broad role shortcuts (`ROLE_SUPER_ADMIN` always allowed) without auditable trail.
            - Inspect ownership checks for nullable / weak-typed comparisons (e.g. `==` on UUID strings, missing user object check).
            - Flag voters that consult only `getRoles()` while the request requires per-resource attribute checks.
            SKILL,
        'entity' => <<<'SKILL'
            ### Entity / Doctrine Specialist Skills
            - Lifecycle callbacks (`#[PrePersist]`, `#[PreUpdate]`) calling unsanitized methods, command execution, or external HTTP.
            - Public setters on sensitive fields (`isAdmin`, `roles`, `passwordHash`) exposed via form normalization.
            - Custom Doctrine types using `convertToPHPValue` with `unserialize` or `eval`-equivalent.
            - DQL/QueryBuilder usage with string concatenation of request input — even inside the entity class.
            - Boolean / enum coercion via Doctrine type juggling that lets attacker promote role string.
            SKILL,
        'repository' => <<<'SKILL'
            ### Repository Specialist Skills
            - DQL/SQL injection via string concatenation in custom finder methods; absence of `setParameter()`.
            - Dynamic `ORDER BY` / `LIMIT` fed from request input — Doctrine does NOT parameterize these.
            - `NativeQuery` / `getConnection()->executeQuery()` with interpolated user input.
            - Methods exposing arbitrary criteria (`findBy(['role' => $userInput])`) where caller forgot to constrain values.
            - Subquery building that bypasses voters/filters applied at the controller layer.
            SKILL,
        'form' => <<<'SKILL'
            ### Form Specialist Skills
            - `'csrf_protection' => false` on forms processing state changes (only acceptable for stateless APIs with their own auth).
            - `'allow_extra_fields' => true` enabling mass assignment of unmapped properties via setters.
            - `EntityType` choice queries unscoped by ownership — attacker can select any other tenant's row.
            - Data transformers that `unserialize` / `json_decode` raw input without strict mode.
            - Missing `'constraints'` on free-form fields that flow into the database or shell.
            SKILL,
        'template' => <<<'SKILL'
            ### Twig Template Specialist Skills
            - `|raw` filter applied to variables originating from user input or untrusted DB content.
            - `autoescape` overridden to `false` or to a context that does not match the surrounding HTML/JS/URL context.
            - `{{ include(user_input) }}` or `{% include %}` with dynamic template names — Server-Side Template Injection (SSTI) vector.
            - Inline JavaScript context (`<script>var x = {{ value }};`) without `|json_encode` — XSS via Twig.
            - URL attributes (`href`, `src`) built from user input without `|url_encode` and protocol whitelist (javascript:, data:).
            SKILL,
        'config' => <<<'SKILL'
            ### Configuration Specialist Skills
            - Hardcoded secrets, API keys, DSNs (look for `_KEY`, `_SECRET`, `_TOKEN`, `password:`, full DSN strings).
            - `security.firewalls` with `security: false` on protected paths, or `access_control` rules with overly broad path patterns.
            - `framework.session.cookie_secure: false` / `cookie_samesite: none` / missing `cookie_httponly` in non-test envs.
            - Dev-only routes (`_profiler`, `_wdt`) not gated by environment or IP allowlist.
            - `cors.allow_origin: '*'` combined with `allow_credentials: true` — credential leak.
            - Exposed services with public `true` that wrap dangerous primitives (filesystem, process, raw SQL).
            SKILL,
        'php' => <<<'SKILL'
            ### Generic PHP Service Specialist Skills
            - Symfony ExpressionLanguage / Security Expression evaluating strings derived from user input.
            - `HttpClientInterface` calls with user-controlled URL or host — SSRF; check for protocol & host allowlist.
            - `unserialize()` / `igbinary_unserialize()` on untrusted payloads (cache values, queue messages, request body).
            - `Process` / `proc_open` / `shell_exec` constructed with user input concatenation; no `escapeshellarg`.
            - PSR-3 logger sinks receiving raw request payloads without redaction (log injection, log forging).
            - Cryptography: `md5`/`sha1` for security purposes, `random_int` vs `rand`/`mt_rand`, hardcoded IVs/keys.
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
            Analyze these files for exploitable vulnerabilities:

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

            Rules:
            - ONLY report REAL vulnerabilities with clear exploitation paths
            - Do NOT report theoretical issues without concrete evidence in the code
            - Focus on issues traditional SAST tools miss: business logic, context-dependent access control
            - Consider the FULL call chain, not just single function calls
            - Cross-reference controllers, voters, services, and entities together
            - Return ONLY the JSON array, no prose, no markdown fences
            PROMPT;
    }

    /**
     * @param list<ProjectFile> $files
     */
    private function skillsForFiles(array $files): string
    {
        $types = [];
        foreach ($files as $file) {
            $types[] = $file->type();
        }

        $types = array_unique($types);
        sort($types);

        $blocks = [];
        foreach ($types as $type) {
            if (isset(self::SKILLS[$type])) {
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
                "### %s [%s]\n```php\n%s\n```",
                $file->relativePath(),
                $file->type(),
                $file->content(),
            );
        }

        return implode("\n\n", $parts);
    }
}
