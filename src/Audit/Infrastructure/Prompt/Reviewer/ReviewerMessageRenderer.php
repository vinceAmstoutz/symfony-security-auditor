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

/** @internal not part of the BC promise, see docs/versioning.md */
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
                %s

                ## Full File Context
                <file path="%s">
                %s
                </file>

                %s
                MSG,
            $data['id'],
            $data['type'],
            $data['severity'],
            $this->stripEmbeddedNewline($this->escapeFences($data['title'])),
            $filePath,
            $data['line_start'],
            $data['line_end'],
            $this->escapeFences($data['description']),
            $this->escapeFences($data['vulnerable_code']),
            $this->escapeFences($data['attack_vector']),
            $this->escapeFences($data['proof']),
            $this->escapeFences($data['remediation']),
            number_format($data['confidence'], 2, '.', ''),
            $filePath,
            $this->numberLines($codeContext),
            $this->singleClosingInstruction($useStructuredCollection),
        );
    }

    /**
     * Gives a file several findings share once, with the first of them; the
     * others point to it.
     *
     * @param list<Vulnerability>   $vulnerabilities
     * @param array<string, string> $codeContexts
     */
    #[Override]
    public function renderBatch(array $vulnerabilities, array $codeContexts, bool $useStructuredCollection): string
    {
        $sections = [];
        $firstFindingOfFile = [];
        foreach ($vulnerabilities as $index => $vulnerability) {
            $findingNumber = $index + 1;
            $filePath = $this->sanitizeFilePath($vulnerability->toArray()['file']);
            $codeContext = $codeContexts[$vulnerability->id()] ?? '';
            $firstFindingOfFile[$filePath][$codeContext] ??= $findingNumber;
            $carryingFinding = $firstFindingOfFile[$filePath][$codeContext];

            $sections[] = $this->renderBatchSection(
                $vulnerability,
                $findingNumber,
                '' === $codeContext || $carryingFinding === $findingNumber
                    ? $this->renderFile($filePath, $codeContext)
                    : \sprintf('The full source of %s is given with Finding %d above.', $filePath, $carryingFinding),
            );
        }

        return \sprintf("## Vulnerability Reports to Review\n\n%s%s", implode("\n\n", $sections), $this->batchClosingInstruction($useStructuredCollection));
    }

    private function renderFile(string $filePath, string $codeContext): string
    {
        return \sprintf("<file path=\"%s\">\n%s\n</file>", $filePath, $this->numberLines($codeContext));
    }

    private function renderBatchSection(Vulnerability $vulnerability, int $findingNumber, string $fileContext): string
    {
        $data = $vulnerability->toArray();

        return \sprintf(
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
                %s

                #### Full File Context
                %s
                MSG,
            $findingNumber,
            $data['id'],
            $data['type'],
            $data['severity'],
            $this->stripEmbeddedNewline($this->escapeFences($data['title'])),
            $this->sanitizeFilePath($data['file']),
            $data['line_start'],
            $data['line_end'],
            $this->escapeFences($data['description']),
            $this->escapeFences($data['vulnerable_code']),
            $this->escapeFences($data['attack_vector']),
            $this->escapeFences($data['proof']),
            $this->escapeFences($data['remediation']),
            number_format($data['confidence'], 2, '.', ''),
            $fileContext,
        );
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
     * Folds line breaks and `"` in the model-written path, so it cannot close
     * the `<file path="...">` tag or forge a paragraph of the prompt.
     */
    private function sanitizeFilePath(string $filePath): string
    {
        return str_replace(["\r", "\n", '"'], [' ', ' ', "'"], $filePath);
    }

    /**
     * Keeps a one-line field such as `Title:` from forging a paragraph of the
     * prompt.
     */
    private function stripEmbeddedNewline(string $text): string
    {
        return str_replace(["\r", "\n"], ' ', $text);
    }

    /**
     * Escapes backticks and `#`, so a model-written field cannot leave its code
     * fence or forge a `###` section of the prompt.
     */
    private function escapeFences(string $text): string
    {
        return str_replace(['`', '#'], ['\\`', '\\#'], $text);
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
