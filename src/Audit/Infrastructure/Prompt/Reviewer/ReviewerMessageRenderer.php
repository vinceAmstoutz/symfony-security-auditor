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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ReviewerMessageRenderer implements ReviewerMessageRendererInterface
{
    #[Override]
    public function renderSingle(Vulnerability $vulnerability, string $codeContext, bool $useStructuredCollection): string
    {
        $data = $vulnerability->toArray();
        $filePath = $this->sanitizeFilePath($data['file']);

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

                %s
                MSG,
            $data['id'],
            $data['type'],
            $data['severity'],
            $data['title'],
            $filePath,
            $data['line_start'],
            $data['line_end'],
            $data['description'],
            $data['vulnerable_code'],
            $data['attack_vector'],
            $data['proof'],
            $data['remediation'],
            $data['confidence'],
            $filePath,
            $this->numberLines($codeContext),
            $this->singleClosingInstruction($useStructuredCollection),
        );
    }

    /**
     * @param list<Vulnerability>   $vulnerabilities
     * @param array<string, string> $codeContexts
     */
    #[Override]
    public function renderBatch(array $vulnerabilities, array $codeContexts, bool $useStructuredCollection): string
    {
        $sections = [];
        foreach ($vulnerabilities as $index => $vulnerability) {
            $data = $vulnerability->toArray();
            $filePath = $this->sanitizeFilePath($data['file']);
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
                $filePath,
                $data['line_start'],
                $data['line_end'],
                $data['description'],
                $data['vulnerable_code'],
                $data['attack_vector'],
                $data['proof'],
                $data['remediation'],
                $data['confidence'],
                $filePath,
                $this->numberLines($codeContext),
            );
        }

        return \sprintf("## Vulnerability Reports to Review\n\n%s%s", implode("\n\n", $sections), $this->batchClosingInstruction($useStructuredCollection));
    }

    private function singleClosingInstruction(bool $useStructuredCollection): string
    {
        if ($useStructuredCollection) {
            return 'Validate this finding and record your verdict via the `record_review` tool.';
        }

        return 'Validate this finding and return your review JSON.';
    }

    private function batchClosingInstruction(bool $useStructuredCollection): string
    {
        if ($useStructuredCollection) {
            return "\n\nRecord one review per finding above via the `record_review` tool. Each call's \"id\" must match the input finding; we re-key by id when collecting your calls, so call order does not matter.";
        }

        return "\n\nReturn a JSON array of reviews — one entry per finding above. Each entry's \"id\" must match the input; we re-key by id on parse, so a misordered array with correct ids will still be accepted.";
    }

    /**
     * The attacker LLM supplies `file_path` as a free-form tool argument,
     * indirectly influenced by whatever text lives in the audited source it
     * just analyzed. A crafted value containing `"` or a newline could
     * otherwise close the `<file path="...">` tag early or forge fake
     * standalone instruction paragraphs in the plain `File: ...` line.
     */
    private function sanitizeFilePath(string $filePath): string
    {
        return str_replace(["\n", '"'], [' ', "'"], $filePath);
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
