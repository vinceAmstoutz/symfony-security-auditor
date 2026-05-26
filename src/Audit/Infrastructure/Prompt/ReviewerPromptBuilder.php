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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ReviewerPromptBuilder implements ReviewerPromptBuilderInterface
{
    private const string SEVERITY_RUBRIC = <<<'RUBRIC'
        Severity rubric (apply this scale when accepting OR when setting adjusted_severity — do not inflate):
        - critical: unauthenticated RCE, full authentication bypass, mass data exfiltration without auth, hardcoded production secret in a committed file.
        - high: authenticated RCE, privilege escalation across tenants, IDOR exposing PII, SQL/DQL injection with a reachable sink, voter bypass on sensitive resources.
        - medium: stored XSS in authenticated views, CSRF on state-changing actions, SSRF reaching internal services, weak crypto guarding non-public secrets.
        - low: reflected XSS in low-impact contexts, information disclosure of non-sensitive metadata, weak crypto on already-public data, missing security headers.
        - info: defense-in-depth opportunities, hardening suggestions, deprecated patterns with no current exploit path.
        RUBRIC;

    private const string FALSE_POSITIVE_PLAYBOOK = <<<'PLAYBOOK'
        Symfony false-positive playbook (REJECT findings that match these patterns — they are NOT vulnerabilities):
        - Doctrine `QueryBuilder` / DQL that uses `setParameter()` for every user-controlled value. Doctrine binds those safely; no SQL injection.
        - Forms using the default CSRF token (Symfony enables it by default). Only an explicit `'csrf_protection' => false` is the smell.
        - Controllers protected by a parent-class `denyAccessUnlessGranted()` call, a class-level `#[IsGranted]`, or an `access_control` rule in `security.yaml` matching the route path.
        - `md5`/`sha1` on non-security data (cache keys, ETags, file fingerprints).
        - `Process` instantiated with a hardcoded argv array — no shell interpolation occurs.
        - Twig `{{ value }}` interpolation in HTML context — auto-escape covers this. Only `|raw`, broken `autoescape`, or wrong-context output (URL, JS) qualify.
        - `_profiler` / `_wdt` routes gated by `when@dev` / `when@test`.
        - Form fields with `mapped: false` whose constraints validate the input — they never reach the entity setter.
        - Reflected user input echoed back as plain text inside a `Response` of `Content-Type: text/plain` (no HTML execution surface).
        - Webhook handlers calling `hash_equals($expected, $received)` against a configured secret — that IS the constant-time check.
        - Messenger transports configured with the framework default JSON serializer (`messenger.transport.symfony_serializer`) — no PHP-native unserialize.
        - `#[MapRequestPayload]` / `#[MapQueryString]` over a DTO with constraint attributes (`#[Assert\…]`) — the validator runs before the controller body.
        - `HtmlSanitizerInterface::sanitize()` output rendered with `|raw` — the sanitizer guarantees XSS-safe HTML.
        - `RateLimiterFactory::create($userIdentifier)` on auth endpoints — per-identity scope is correct.
        - `LockFactory::createLock($resourceId)` around a critical section — that IS the mitigation for race conditions.
        Reject these with a one-line note pointing at the specific mitigation.
        PLAYBOOK;

    private const string CORE_INSTRUCTIONS = <<<'CORE'
        You are a senior AppSec engineer and security code reviewer.
        Your role is to CRITICALLY VALIDATE vulnerability reports from an automated scanner.

        You must be SKEPTICAL and RIGOROUS. Your job is to eliminate false positives.

        For each vulnerability:
        1. Verify the vulnerable code actually exists at the stated location (the `Full File Context` is line-numbered; match `line_start`/`line_end` against those numbers).
        2. Confirm the attack vector is technically feasible
        3. Check if there are mitigating controls not seen by the attacker agent
        4. Validate that the severity rating is appropriate
        5. Validate that the `type` accurately describes the finding — set `corrected_type` if mislabeled
        6. Assess if the proof-of-concept is realistic

        You must consider:
        - Symfony's built-in protections (CSRF tokens, firewall, parameter validation)
        - Framework-level mitigations (Doctrine parameterized queries by default)
        - Existing Voters that might protect the resource
        - HTTP method restrictions and route constraints
        - Whether the code is actually reachable in production
        CORE;

    private const string JSON_SCHEMA_DESCRIPTION = <<<'SCHEMA'
        Each entry of the JSON array MUST be shaped:
        {
          "id": "<vulnerability id, must match the input>",
          "accepted": <true|false>,
          "adjusted_severity": "<critical|high|medium|low|info or null if unchanged>",
          "corrected_type": "<valid vulnerability type string or null if the attacker's type is correct>",
          "reviewer_notes": "<concise technical justification>",
          "additional_attack_paths": "<any additional exploitation paths found, or null>"
        }

        Valid `corrected_type` values (same enum the attacker uses):
        sql_injection, command_injection, ldap_injection, xpath_injection, twig_injection, header_injection,
        broken_access_control, missing_voter, voter_bypass, role_escalation, insecure_direct_object_reference,
        missing_csrf_protection, business_logic_flaw, race_condition, insecure_workflow, price_manipulation,
        state_machine_bypass, mass_assignment, insecure_deserialization, unsafe_parameter_binding,
        exposed_internal_service, misconfigured_firewall, insecure_redirect, sensitive_data_exposure,
        log_injection, path_traversal, ssrf, xxe, open_redirect, weak_cryptography, insecure_random,
        hardcoded_secret, missing_signature_verification, messenger_handler_unsafe, missing_rate_limiting,
        cache_poisoning, mailer_header_injection, webhook_replay, authenticator_bypass
        SCHEMA;

    private const string DECISION_RULES = <<<'RULES'
        Rules:
        - Be strict: reject any finding where exploitation is not clearly demonstrated
        - Accept a finding if it represents a REAL risk, even if exploitation is complex
        - You MAY upgrade severity if context reveals a worse impact
        - You MAY downgrade if the scanner overstated impact
        - You MAY set `corrected_type` if the attacker labelled the finding with the wrong vulnerability type but the underlying issue is real
        - Return ONLY the JSON array, no prose
        RULES;

    private const string TOOL_USAGE_DISCIPLINE = <<<'TOOLS'
        Tool usage (when tools are available):
        - You may call `read_file`, `grep`, `list_files`, and `lookup_advisory` to verify cross-file context — e.g. is there a parent-class `denyAccessUnlessGranted()`, an `access_control` rule in security.yaml, a CSRF guard on the route, or an upstream sanitizer?
        - Each call costs the audit budget. Stop calling tools as soon as you have enough evidence to accept or reject the finding.
        - If your initial read of the Full File Context is already sufficient, do NOT call tools — emit the JSON answer directly.
        - Tools are for cross-file checks only. Do not call tools to re-read the file you already have in `Full File Context`.
        - Once you have decided, your response MUST contain ONLY the JSON output — no prose, no further tool calls.
        TOOLS;

    public function buildSystemPrompt(): string
    {
        return implode("\n\n", [
            self::CORE_INSTRUCTIONS,
            self::SEVERITY_RUBRIC,
            self::FALSE_POSITIVE_PLAYBOOK,
            'Your output must be a JSON array, one entry per vulnerability reviewed.',
            self::JSON_SCHEMA_DESCRIPTION,
            self::DECISION_RULES,
            self::TOOL_USAGE_DISCIPLINE,
        ]);
    }

    public function buildBatchSystemPrompt(): string
    {
        $batchPreamble = 'You will receive SEVERAL vulnerability reports in a single batch and must validate each one.';

        $orderingInstruction = 'Findings are re-keyed by "id" when we parse your response, so the id field is the source of truth — keep the natural order shown above for your scratch reasoning, but a misordered array with correct ids will still be accepted.';

        // See buildSystemPrompt() for why this is implode + array, not a
        // concat chain.
        return implode("\n\n", [
            self::CORE_INSTRUCTIONS,
            $batchPreamble,
            self::SEVERITY_RUBRIC,
            self::FALSE_POSITIVE_PLAYBOOK,
            'Your output MUST be a JSON array with EXACTLY one entry per input vulnerability.',
            self::JSON_SCHEMA_DESCRIPTION,
            $orderingInstruction,
            self::DECISION_RULES,
            self::TOOL_USAGE_DISCIPLINE,
        ]);
    }

    public function buildBatchUserMessage(array $vulnerabilities, array $codeContexts): string
    {
        $sections = [];
        foreach ($vulnerabilities as $index => $vulnerability) {
            $data = $vulnerability->toArray();
            $codeContext = $codeContexts[$vulnerability->id()] ?? '';
            $sections[] = \sprintf(
                <<<'MSG'
                    ### Finding %d
                    ID: %s
                    Type: %s
                    Severity: %s
                    Title: %s
                    File: %s (lines %d-%d)

                    #### Description
                    %s

                    #### Vulnerable Code
                    ```
                    %s
                    ```

                    #### Attack Vector
                    %s

                    #### Proof of Concept
                    %s

                    #### Remediation
                    %s

                    #### Confidence
                    %.2f

                    #### Full File Context
                    <file path="%s">
                    %s
                    </file>
                    MSG,
                $index + 1,
                $data['id'],
                $data['type'],
                $data['severity'],
                $data['title'],
                $data['file'],
                $data['line_start'],
                $data['line_end'],
                $data['description'],
                $data['vulnerable_code'],
                $data['attack_vector'],
                $data['proof'],
                $data['remediation'],
                $data['confidence'],
                $data['file'],
                $this->numberLines($codeContext),
            );
        }

        return "## Vulnerability Reports to Review\n\n".implode("\n\n", $sections)
            ."\n\nReturn a JSON array of reviews — one entry per finding above. Each entry's \"id\" must match the input; we re-key by id on parse, so a misordered array with correct ids will still be accepted.";
    }

    public function buildUserMessage(Vulnerability $vulnerability, string $codeContext): string
    {
        $data = $vulnerability->toArray();

        return \sprintf(
            <<<'MSG'
                ## Vulnerability Report to Review

                ID: %s
                Type: %s
                Severity: %s
                Title: %s
                File: %s (lines %d-%d)

                ### Description
                %s

                ### Vulnerable Code
                ```
                %s
                ```

                ### Attack Vector
                %s

                ### Proof of Concept
                %s

                ### Remediation
                %s

                ### Confidence
                %.2f

                ## Full File Context
                <file path="%s">
                %s
                </file>

                Validate this finding and return your review JSON.
                MSG,
            $data['id'],
            $data['type'],
            $data['severity'],
            $data['title'],
            $data['file'],
            $data['line_start'],
            $data['line_end'],
            $data['description'],
            $data['vulnerable_code'],
            $data['attack_vector'],
            $data['proof'],
            $data['remediation'],
            $data['confidence'],
            $data['file'],
            $this->numberLines($codeContext),
        );
    }

    private function numberLines(string $content): string
    {
        if ('' === $content) {
            return '';
        }

        $lines = explode("\n", $content);
        $numbered = [];
        foreach ($lines as $index => $line) {
            $numbered[] = \sprintf('%3d | %s', $index + 1, $line);
        }

        return implode("\n", $numbered);
    }
}
