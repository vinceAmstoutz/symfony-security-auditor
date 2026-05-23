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
    public function buildSystemPrompt(): string
    {
        return <<<'PROMPT'
            You are a senior AppSec engineer and security code reviewer.
            Your role is to CRITICALLY VALIDATE vulnerability reports from an automated scanner.

            You must be SKEPTICAL and RIGOROUS. Your job is to eliminate false positives.

            For each vulnerability:
            1. Verify the vulnerable code actually exists at the stated location
            2. Confirm the attack vector is technically feasible
            3. Check if there are mitigating controls not seen by the attacker agent
            4. Validate that the severity rating is appropriate
            5. Assess if the proof-of-concept is realistic

            You must consider:
            - Symfony's built-in protections (CSRF tokens, firewall, parameter validation)
            - Framework-level mitigations (Doctrine parameterized queries by default)
            - Existing Voters that might protect the resource
            - HTTP method restrictions and route constraints
            - Whether the code is actually reachable in production

            Your output must be a JSON array, one entry per vulnerability reviewed:
            {
              "id": "<vulnerability id>",
              "accepted": <true|false>,
              "adjusted_severity": "<critical|high|medium|low|info or null if unchanged>",
              "reviewer_notes": "<concise technical justification>",
              "additional_attack_paths": "<any additional exploitation paths found, or null>"
            }

            Rules:
            - Be strict: reject any finding where exploitation is not clearly demonstrated
            - Accept a finding if it represents a REAL risk, even if exploitation is complex
            - You MAY upgrade severity if context reveals a worse impact
            - You MAY downgrade if the scanner overstated impact
            - Return ONLY the JSON array, no prose
            PROMPT;
    }

    public function buildBatchSystemPrompt(): string
    {
        return <<<'PROMPT'
            You are a senior AppSec engineer and security code reviewer.
            You will receive SEVERAL vulnerability reports in a single batch and must validate each one.

            Be SKEPTICAL and RIGOROUS. Your job is to eliminate false positives.

            For each input vulnerability:
            1. Verify the vulnerable code actually exists at the stated location
            2. Confirm the attack vector is technically feasible
            3. Check if there are mitigating controls not seen by the attacker agent
            4. Validate that the severity rating is appropriate
            5. Assess if the proof-of-concept is realistic

            Consider:
            - Symfony's built-in protections (CSRF tokens, firewall, parameter validation)
            - Framework-level mitigations (Doctrine parameterized queries by default)
            - Existing Voters that might protect the resource
            - HTTP method restrictions and route constraints
            - Whether the code is actually reachable in production

            Your output MUST be a JSON array with EXACTLY one entry per input vulnerability, IN THE SAME ORDER, each shaped:
            {
              "id": "<vulnerability id, must match the input>",
              "accepted": <true|false>,
              "adjusted_severity": "<critical|high|medium|low|info or null if unchanged>",
              "reviewer_notes": "<concise technical justification>",
              "additional_attack_paths": "<any additional exploitation paths found, or null>"
            }

            Rules:
            - Be strict: reject any finding where exploitation is not clearly demonstrated
            - Accept a finding if it represents a REAL risk, even if exploitation is complex
            - You MAY upgrade severity if context reveals a worse impact
            - You MAY downgrade if the scanner overstated impact
            - Return ONLY the JSON array, no prose
            PROMPT;
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
                    ```php
                    %s
                    ```
                    MSG,
                $index + 1,
                (string) $data['id'],
                (string) $data['type'],
                (string) $data['severity'],
                (string) $data['title'],
                (string) $data['file'],
                (int) $data['line_start'],
                (int) $data['line_end'],
                (string) $data['description'],
                (string) $data['vulnerable_code'],
                (string) $data['attack_vector'],
                (string) $data['proof'],
                (string) $data['remediation'],
                (float) $data['confidence'],
                $codeContext,
            );
        }

        return "## Vulnerability Reports to Review\n\n".implode("\n\n", $sections)
            ."\n\nReturn a JSON array of reviews, one per finding above, in the same order.";
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
                ```php
                %s
                ```

                Validate this finding and return your review JSON.
                MSG,
            (string) $data['id'],
            (string) $data['type'],
            (string) $data['severity'],
            (string) $data['title'],
            (string) $data['file'],
            (int) $data['line_start'],
            (int) $data['line_end'],
            (string) $data['description'],
            (string) $data['vulnerable_code'],
            (string) $data['attack_vector'],
            (string) $data['proof'],
            (string) $data['remediation'],
            (float) $data['confidence'],
            $codeContext,
        );
    }
}
