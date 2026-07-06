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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AttackerPromptBuilder implements AttackerPromptBuilderInterface
{
    /**
     * Wire-format version of the prompt this builder emits. Folded into the
     * attacker cache key so that a wording change automatically invalidates
     * previously-cached LLM responses. Bump whenever the prompt structure or
     * skill blocks change in a way the LLM is expected to react to.
     */
    public const int PROMPT_VERSION = 15;

    public const bool DEFAULT_STRUCTURED_COLLECTION = true;

    public const bool DEFAULT_EMIT_ALL_SKILLS = false;

    public function __construct(
        private bool $useStructuredCollection = self::DEFAULT_STRUCTURED_COLLECTION,
        private bool $emitAllSkills = self::DEFAULT_EMIT_ALL_SKILLS,
        private AttackerSkillRegistry $attackerSkillRegistry = new AttackerSkillRegistry(),
    ) {}

    /**
     * @param list<ProjectFile> $files
     */
    #[Override]
    public function buildSystemPrompt(array $files = []): string
    {
        $base = $this->basePrompt();

        $skills = $this->skillsForFiles($files);

        if ('' === $skills) {
            return $base;
        }

        return \sprintf("%s\n\n%s", $base, $skills);
    }

    /**
     * @param list<ProjectFile> $files
     */
    #[Override]
    public function buildUserMessage(array $files, SymfonyMapping $symfonyMapping): string
    {
        $context = NumberedFileContextRenderer::render($files);
        $summary = $symfonyMapping->toSummary();

        $noVoterList = implode("\n", array_map(
            static fn (ProjectFile $projectFile): string => \sprintf('  - %s', $projectFile->relativePath()),
            $symfonyMapping->controllersWithoutVoters(),
        ));

        $accessControlMap = SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping);
        $voterCoverage = SymfonyMappingContextRenderer::renderVoterCoverage($symfonyMapping);
        $formBindings = SymfonyMappingContextRenderer::renderFormBindings($symfonyMapping);
        $closingInstruction = $this->closingInstruction();

        return <<<PROMPT
            ## Project Mapping Summary
            {$summary}

            ## Controllers WITHOUT Security Annotations (High Priority)
            {$noVoterList}

            {$accessControlMap}{$voterCoverage}{$formBindings}## Source Code
            Analyze these files for exploitable vulnerabilities. Each line is prefixed with its line number (`NNN | code`) — use those exact numbers when populating `line_start` and `line_end`; do NOT count manually or guess.

            {$context}

            {$closingInstruction}
            PROMPT;
    }

    private function closingInstruction(): string
    {
        if ($this->useStructuredCollection) {
            return 'Record every vulnerability you find via the `record_vulnerability` tool — one call per finding.';
        }

        return 'Return a JSON array of all vulnerabilities found.';
    }

    private function basePrompt(): string
    {
        return $this->basePromptIntro()
            .$this->outputFormatSection()
            .$this->severityAndConfidenceRubrics()
            .$this->fileNumberingAndScope()
            .$this->analysisMethodology()
            .$this->exampleFinding()
            .$this->rulesAndToolDiscipline();
    }

    private function basePromptIntro(): string
    {
        return <<<'PROMPT'
            You are an elite offensive security researcher and red team expert specializing in Symfony and PHP applications.
            Your mission is to think like a sophisticated attacker and find REAL, EXPLOITABLE vulnerabilities.

            You have deep expertise in:
            - Symfony internals (7.x/8.x): Voters, Authenticators, EventListeners, Forms, Serializer, Security component, Messenger, Webhook, Schedule, RateLimiter, Lock, HtmlSanitizer
            - PHP deserialization gadget chains
            - Doctrine ORM injection patterns (DQL injection, query builder abuse)
            - Twig SSTI (Server Side Template Injection) and Twig Components / Live Components vectors
            - Symfony routing and access control bypass patterns (firewall rules, access_control, voters)
            - Business logic and workflow exploitation
            - Mass assignment via Symfony Forms, ParamConverter, `#[MapRequestPayload]`, Serializer denormalizers
            - CSRF token bypass techniques specific to Symfony
            - Broken Voters and missing denyAccessUnlessGranted() calls
            - Complex multi-step injection paths through service chains
            - Messenger transports: PHP serializer abuse, missing idempotency, replay attacks via queues
            - Webhook signature verification gaps (HMAC, timing-attack via `==`/`===`, replay protection)
            - OAuth/OIDC handlers, AccessTokenHandler audience/issuer/signature gaps, `state`/PKCE bypass
            - Custom Authenticator failure modes: `SelfValidatingPassport` misuse, `supports()` returning null
            - Cache poisoning, mailer header injection, rate-limiter scope confusion


            PROMPT;
    }

    private function outputFormatSection(): string
    {
        if ($this->useStructuredCollection) {
            return <<<'PROMPT'
                Your output MUST be expressed via `record_vulnerability` tool calls — one call per finding. The platform validates each call against the tool's input schema, so malformed shapes (bare strings, env names, wrapper objects) cannot be emitted. Do NOT emit JSON arrays, prose listings, or any text-based enumeration of findings.
                Each tool call accepts these arguments (the input schema is authoritative):
                  type:            one of the valid vulnerability type values
                  severity:        critical | high | medium | low | info
                  title:           short headline
                  description:     detailed technical description (required)
                  file_path:       project-relative path (required)
                  line_start:      first line number from the NNN | prefix
                  line_end:        last line number (= line_start for single-line findings)
                  vulnerable_code: the actual vulnerable code snippet
                  attack_vector:   step-by-step exploitation path
                  proof:           concrete proof of concept or payload
                  remediation:     specific fix with code example
                  confidence:      0.0-1.0 float


                PROMPT;
        }

        return <<<'PROMPT'
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


            PROMPT;
    }

    private function severityAndConfidenceRubrics(): string
    {
        return <<<'PROMPT'
            Valid type values:
            sql_injection, command_injection, ldap_injection, xpath_injection, twig_injection, header_injection,
            broken_access_control, missing_voter, voter_bypass, role_escalation, insecure_direct_object_reference,
            missing_csrf_protection, business_logic_flaw, race_condition, insecure_workflow, price_manipulation,
            state_machine_bypass, mass_assignment, insecure_deserialization, unsafe_parameter_binding,
            exposed_internal_service, misconfigured_firewall, insecure_redirect, sensitive_data_exposure,
            log_injection, path_traversal, ssrf, xxe, open_redirect, weak_cryptography, insecure_random,
            hardcoded_secret, missing_signature_verification, messenger_handler_unsafe, missing_rate_limiting,
            cache_poisoning, mailer_header_injection, webhook_replay, authenticator_bypass,
            over_permissive_serializer_group

            Severity rubric (calibrate every finding against this scale — do NOT inflate severity for emphasis):
            - critical: unauthenticated RCE, full authentication bypass, mass data exfiltration without auth, hardcoded production secret in a committed file.
            - high: authenticated RCE, privilege escalation across tenants, IDOR exposing PII, SQL/DQL injection with a reachable sink, voter bypass on sensitive resources.
            - medium: stored XSS in authenticated views, CSRF on state-changing actions, SSRF reaching internal services, weak crypto guarding non-public secrets.
            - low: reflected XSS in low-impact contexts, information disclosure of non-sensitive metadata, weak crypto on already-public data, missing security headers.
            - info: defense-in-depth opportunities, hardening suggestions, deprecated patterns with no current exploit path.

            Exposure weighting: severity is risk (roughly likelihood times impact), not bug class alone. Raise severity when the vulnerable path is reachable by an unauthenticated or low-privilege actor (public route, anonymous firewall, pre-auth handler, webhook); lower it when reachable only behind strong authentication or by trusted/admin roles. Weigh exploitability and the sensitivity of the affected data rather than a generic CVSS guess.

            Confidence rubric (filtered downstream — entries below 0.6 are dropped before reviewer):
            - 0.9-1.0: tainted source traced to dangerous sink with concrete payload.
            - 0.7-0.89: clear vulnerable pattern matched, exploitation plausible without a full PoC.
            - 0.6-0.69: pattern smell that needs reviewer adjudication.
            - Below 0.6: do NOT report — it will be filtered and waste reviewer budget.


            PROMPT;
    }

    private function fileNumberingAndScope(): string
    {
        return <<<'PROMPT'
            File-numbering protocol:
            Each line of every source file is prefixed with `NNN | ` (line number, space, pipe, space). Populate `line_start` / `line_end` using those exact numbers — never count or estimate. If a finding spans a single line, set `line_end == line_start`.

            Scope:
            - Only report findings in the source files provided below. Ignore code under `vendor/`, `var/cache/`, `var/log/`, any path containing `.generated.` or `.cache.`, and obvious build artifacts.
            - If a finding references code outside the provided chunk, set `confidence` no higher than 0.7 and explain the cross-file dependency in `attack_vector`.


            PROMPT;
    }

    private function analysisMethodology(): string
    {
        return <<<'PROMPT'
            Analysis methodology — apply to every candidate before recording it:
            - Source (trust boundary): identify the attacker-controlled entry point the value crosses from — route/path parameter, query string, request body, header, cookie, uploaded file, or webhook/queue payload (and anything derived from them).
            - Flow: trace that value through each assignment, transformation, and cross-file call to the sink, noting any sanitizer, validator, parameterized query, escaping, or access-control check on the path.
            - Sink: confirm it reaches a dangerous operation (SQL/DQL, shell/process, file path, Twig, redirect, deserialization, reflected/stored output, or a privileged state change) with no mitigating control in between.
            - Verify before recording: record ONLY when the value is genuinely attacker-controlled, reaches the sink on a reachable path, and nothing on the path (guard clause, validator, parameterization, escaping, `access_control`, voter) neutralizes it. Otherwise do not record — or lower `confidence` and state the missing link in `attack_vector`. Always name the concrete source, sink, and path.

            For each entry point, sweep the STRIDE categories so no class is skipped:
            - Spoofing: authentication or identity-check bypass (authenticator flaws, forgeable or replayable tokens).
            - Tampering: mass assignment, unvalidated writes, parameter binding to privileged fields.
            - Repudiation: privileged or balance-affecting actions with no audit trail or idempotency key.
            - Information disclosure: IDOR, over-permissive serializer groups, verbose errors, sensitive data in logs.
            - Denial of service: unbounded loops/uploads/recursion, missing rate limiting on costly or auth endpoints.
            - Elevation of privilege: missing `#[IsGranted]` / `denyAccessUnlessGranted()`, broken voter, role escalation.


            PROMPT;
    }

    private function exampleFinding(): string
    {
        if ($this->useStructuredCollection) {
            return <<<'PROMPT'
                Example finding (illustrative — do NOT echo this in your output):
                Input file `src/Controller/InvoiceController.php`:
                  42 |     public function show(int $id, InvoiceRepository $repo): Response
                  43 |     {
                  44 |         $invoice = $repo->find($id);
                  45 |         return $this->render('invoice/show.html.twig', ['invoice' => $invoice]);
                  46 |     }
                Expected behavior: call `record_vulnerability` once with arguments equivalent to:
                  type=insecure_direct_object_reference, severity=high,
                  title="IDOR on invoice show action",
                  description="The show() action fetches an Invoice by id without verifying that the current user owns it. Any authenticated user can view any invoice by changing the path parameter.",
                  file_path="src/Controller/InvoiceController.php", line_start=42, line_end=46,
                  vulnerable_code="$invoice = $repo->find($id);",
                  attack_vector="1. Authenticate as user A. 2. Browse to /invoice/{B's invoice id}. 3. Server returns the invoice without ownership check.",
                  proof="GET /invoice/9999 → 200 with another tenant's invoice payload.",
                  remediation="Add `\$this->denyAccessUnlessGranted('VIEW', \$invoice);` after fetch, or query the repository scoped to `\$this->getUser()`.",
                  confidence=0.9.


                PROMPT;
        }

        return <<<'PROMPT'
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


            PROMPT;
    }

    private function rulesAndToolDiscipline(): string
    {
        if ($this->useStructuredCollection) {
            return <<<'PROMPT'
                Rules:
                - ONLY report REAL vulnerabilities with clear exploitation paths
                - Do NOT report theoretical issues without concrete evidence in the code
                - Focus on issues traditional SAST tools miss: business logic, context-dependent access control
                - Consider the FULL call chain, not just single function calls
                - Cross-reference controllers, voters, services, and entities together
                - Record findings ONLY by calling the `record_vulnerability` tool — one call per finding. Do NOT emit prose, JSON, or any other listing of findings.
                - When no vulnerabilities are found, call no tools and finish with an empty response. NEVER call `record_vulnerability` with a placeholder, label, environment name, or "no findings" payload.

                Tool Usage Discipline:
                - You have a LIMITED, finite tool-call budget per chunk. Do NOT call `record_vulnerability` speculatively — only when you have concrete evidence of an exploitable finding.
                - The moment you have decided on the complete set of findings, stop calling tools and finish your turn. Continuing "to be thorough" wastes the budget.
                - If your scan of the provided files surfaces no exploitable findings, finish immediately with no tool calls.
                PROMPT;
        }

        return <<<'PROMPT'
            Rules:
            - ONLY report REAL vulnerabilities with clear exploitation paths
            - Do NOT report theoretical issues without concrete evidence in the code
            - Focus on issues traditional SAST tools miss: business logic, context-dependent access control
            - Consider the FULL call chain, not just single function calls
            - Cross-reference controllers, voters, services, and entities together
            - Return ONLY the JSON array, no prose, no markdown fences
            - Every element of the JSON array MUST be a vulnerability object of the exact shape above. NEVER emit a bare string, number, boolean, or null as an array element. When no vulnerabilities are found, return `[]` — never `["no findings"]`, `["safe"]`, or any prose substitute.
            - The top-level value MUST be a JSON array (`[...]`). NEVER wrap findings in an object such as `{"vulnerabilities": [...]}`, `{"findings": [...]}`, `{"dev": [...], "test": [...]}`, or any environment-keyed map. If you want to indicate which environment a finding applies to, put that information inside the `description` or `attack_vector` field of the vulnerability object — never as a separate array element or wrapper key.
            - Environment names, group names, role names, and other short identifiers (`"dev"`, `"test"`, `"prod"`, `"local"`, `"staging"`, `"ROLE_USER"`, …) extracted from the analyzed source code are NEVER valid array elements. Forbidden shape: `["dev", "test", {...vulnerability...}]`. Required shape: `[{...vulnerability...}]` — mention the environment inside the object's text fields instead.

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
            static fn (ProjectFile $projectFile): ProjectFileType => $projectFile->fileType(),
            $files,
        );

        return $this->attackerSkillRegistry->render($presentTypes, $this->emitAllSkills);
    }
}
