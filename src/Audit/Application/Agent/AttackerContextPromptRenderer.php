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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Renders the two prompt preambles the attacker prepends to a chunk's user
 * message: deterministic pre-scan risk markers and the patterns already
 * confirmed by the reviewer in earlier iterations.
 */
final readonly class AttackerContextPromptRenderer
{
    /**
     * @param list<RiskMarker> $markers
     */
    public function renderRiskMarkers(array $markers): string
    {
        $byFile = [];
        foreach ($markers as $marker) {
            $byFile[$marker->filePath()][] = \sprintf(
                'L%d %s — %s',
                $marker->line(),
                $marker->pattern(),
                $marker->description(),
            );
        }

        $blocks = [];
        foreach ($byFile as $filePath => $lines) {
            $blocks[] = \sprintf("%s:\n%s", $filePath, $this->indent(implode("\n", $lines)));
        }

        return <<<PROMPT
            ## Pre-Scan Risk Markers (Deterministic Hints)
            A static pre-scanner flagged the locations below in the chunk. They are NOT confirmed vulnerabilities — only patterns worth investigating. Use them to focus your analysis; ignore markers that the surrounding context proves safe.

            {$this->indent(implode("\n", $blocks))}
            PROMPT;
    }

    /**
     * @param list<Vulnerability> $previousFindings
     */
    public function renderPreviousFindings(array $previousFindings): string
    {
        $byType = [];
        foreach ($previousFindings as $previouFinding) {
            $byType[$previouFinding->type()->value][] = \sprintf(
                '%s:%d-%d',
                $previouFinding->filePath(),
                $previouFinding->lineStart(),
                $previouFinding->lineEnd(),
            );
        }

        $lines = [];
        foreach ($byType as $type => $locations) {
            $lines[] = \sprintf('- %s: %s', $type, implode(', ', $locations));
        }

        return <<<PROMPT
            ## Patterns Already Confirmed in Earlier Iterations
            The reviewer has already validated the findings below. Look for the SAME PATTERNS in files not yet covered by these locations. Do NOT re-report the same vulnerability at the same line range — those entries will be filtered as duplicates.

            {$this->indent(implode("\n", $lines))}

            Generalize: if `insecure_direct_object_reference` was confirmed in one controller, hunt for the same idiom in every other controller in this chunk. If `sql_injection` was confirmed in one repository, look for unsafe DQL/SQL concatenation in every other repository.
            PROMPT;
    }

    /**
     * @param list<Vulnerability> $rejectedFindings
     */
    public function renderRejectedFindings(array $rejectedFindings): string
    {
        $byType = [];
        foreach ($rejectedFindings as $rejectedFinding) {
            $byType[$rejectedFinding->type()->value][] = \sprintf(
                '%s:%d-%d',
                $rejectedFinding->filePath(),
                $rejectedFinding->lineStart(),
                $rejectedFinding->lineEnd(),
            );
        }

        $lines = [];
        foreach ($byType as $type => $locations) {
            $lines[] = \sprintf('- %s: %s', $type, implode(', ', $locations));
        }

        return <<<PROMPT
            ## Findings Already Rejected by the Reviewer
            The reviewer reviewed and REJECTED the findings below in earlier iterations — a mitigating control was found, or the report was a false positive. Do NOT re-report these locations; they only burn the tool-call and reviewer budget. Spend your effort on code these entries do not already cover.

            {$this->indent(implode("\n", $lines))}
            PROMPT;
    }

    private function indent(string $content): string
    {
        return implode("\n", array_map(static fn (string $line): string => \sprintf('  %s', $line), explode("\n", $content)));
    }
}
