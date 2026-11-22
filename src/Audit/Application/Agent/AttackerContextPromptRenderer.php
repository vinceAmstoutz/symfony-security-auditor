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
 * Renders the preambles the attacker prepends to a chunk's user message: the
 * pre-scan risk markers, the findings the reviewer confirmed or rejected in
 * earlier iterations and the unverified candidates of a cheaper first pass.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AttackerContextPromptRenderer
{
    private const int MAX_TITLE_LENGTH = 120;

    private const int MAX_LISTED_MARKERS_PER_PATTERN = 20;

    private const int MAX_LISTED_LOCATIONS = 100;

    /**
     * Lists the markers of a file's pattern up to a cap and counts the rest.
     *
     * @param list<RiskMarker> $markers
     */
    public function renderRiskMarkers(array $markers): string
    {
        $blocks = [];
        foreach ($this->markerLinesByFile($markers) as $filePath => $lines) {
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
        $lines = $this->locationLines($previousFindings);

        return <<<PROMPT
            ## Patterns Already Confirmed in Earlier Iterations
            The reviewer has already validated the findings below, or the project's baseline has accepted them. Look for the SAME PATTERNS in files not yet covered by these locations. Do NOT re-report the same vulnerability at the same line range — those entries will be filtered as duplicates.

            {$this->indent(implode("\n", $lines))}

            Generalize: if `insecure_direct_object_reference` was confirmed in one controller, hunt for the same idiom in every other controller in this chunk. If `sql_injection` was confirmed in one repository, look for unsafe DQL/SQL concatenation in every other repository.
            PROMPT;
    }

    /**
     * @param list<Vulnerability> $rejectedFindings
     */
    public function renderRejectedFindings(array $rejectedFindings): string
    {
        $lines = $this->locationLines($rejectedFindings);

        return <<<PROMPT
            ## Findings Already Rejected by the Reviewer
            The reviewer reviewed and REJECTED the findings below in earlier iterations — a mitigating control was found, or the report was a false positive. Do NOT re-report these locations; they only burn the tool-call and reviewer budget. Spend your effort on code these entries do not already cover.

            {$this->indent(implode("\n", $lines))}
            PROMPT;
    }

    /**
     * @param list<Vulnerability> $candidateFindings
     */
    public function renderCandidateFindings(array $candidateFindings): string
    {
        $lines = [];
        foreach ($candidateFindings as $candidateFinding) {
            $lines[] = \sprintf(
                '- %s: %s:%d-%d (%s, confidence %.2f) — %s',
                $candidateFinding->type()->value,
                $this->sanitizeLine($candidateFinding->filePath()),
                $candidateFinding->lineStart(),
                $candidateFinding->lineEnd(),
                $candidateFinding->severity()->value,
                $candidateFinding->confidence(),
                $this->delimitTitle($candidateFinding->title()),
            );
        }

        return <<<PROMPT
            ## Candidate Findings From a First-Pass Model (Unverified)
            A cheaper model swept these files first and reported the candidates below. They are NOT validated: treat each one as a lead. Confirm it against the code, refine its type, severity, line range or description, or discard it when the surrounding context proves it safe. Re-report every candidate you confirm at the lines you verified — a confirmed candidate you leave out is lost — then look past them for what the first pass missed.

            {$this->indent(implode("\n", $lines))}
            PROMPT;
    }

    /**
     * @param list<RiskMarker> $markers
     *
     * @return array<string, list<string>>
     */
    private function markerLinesByFile(array $markers): array
    {
        $lines = [];
        $countsByFileAndPattern = [];
        foreach ($markers as $marker) {
            $filePath = $this->sanitizeLine($marker->filePath());
            $pattern = $this->sanitizeLine($marker->pattern());
            $count = ($countsByFileAndPattern[$filePath][$pattern] ?? 0) + 1;
            $countsByFileAndPattern[$filePath][$pattern] = $count;

            if ($count <= self::MAX_LISTED_MARKERS_PER_PATTERN) {
                $lines[$filePath][] = \sprintf('L%d %s — %s', $marker->line(), $pattern, $this->sanitizeLine($marker->description()));
            }
        }

        return $this->withUnlistedCounts($lines, $countsByFileAndPattern);
    }

    /**
     * @param array<string, list<string>>       $lines
     * @param array<string, array<string, int>> $countsByFileAndPattern
     *
     * @return array<string, list<string>>
     */
    private function withUnlistedCounts(array $lines, array $countsByFileAndPattern): array
    {
        foreach ($countsByFileAndPattern as $filePath => $countsByPattern) {
            foreach ($countsByPattern as $pattern => $count) {
                if ($count > self::MAX_LISTED_MARKERS_PER_PATTERN) {
                    $lines[$filePath][] = \sprintf('+%d more %s markers not listed', $count - self::MAX_LISTED_MARKERS_PER_PATTERN, $pattern);
                }
            }
        }

        return $lines;
    }

    /**
     * Lists each type with the locations of at most
     * {@see self::MAX_LISTED_LOCATIONS} of its findings.
     *
     * @param list<Vulnerability> $findings
     *
     * @return list<string>
     */
    private function locationLines(array $findings): array
    {
        $listed = \array_slice($findings, 0, self::MAX_LISTED_LOCATIONS);

        $byType = [];
        foreach ($listed as $finding) {
            $byType[$finding->type()->value][] = \sprintf(
                '%s:%d-%d',
                $this->sanitizeLine($finding->filePath()),
                $finding->lineStart(),
                $finding->lineEnd(),
            );
        }

        $lines = [];
        foreach ($byType as $type => $locations) {
            $lines[] = \sprintf('- %s: %s', $type, implode(', ', $locations));
        }

        $notListed = \count($findings) - \count($listed);
        if ($notListed > 0) {
            $lines[] = \sprintf('- … and %d more not listed', $notListed);
        }

        return $lines;
    }

    private function indent(string $content): string
    {
        return implode("\n", array_map(static fn (string $line): string => \sprintf('  %s', $line), explode("\n", $content)));
    }

    /**
     * Quotes a candidate title, a model's free text about untrusted code, so
     * the deep pass reads it as data: folds its double quotes so none closes
     * the quote early and caps its length.
     */
    private function delimitTitle(string $title): string
    {
        $singleLine = str_replace('"', "'", $this->sanitizeLine($title));

        if (mb_strlen($singleLine, 'UTF-8') > self::MAX_TITLE_LENGTH) {
            $singleLine = \sprintf('%s…', mb_substr($singleLine, 0, self::MAX_TITLE_LENGTH, 'UTF-8'));
        }

        return \sprintf('"%s"', $singleLine);
    }

    /**
     * Collapses an untrusted value (a risk-marker text, a file path) to one
     * line, every Unicode line break included, so it cannot forge a `##`
     * section of the prompt.
     */
    private function sanitizeLine(string $value): string
    {
        $scrubbed = mb_scrub($value, 'UTF-8');

        return preg_replace('/\R/u', ' ', $scrubbed) ?? $scrubbed;
    }
}
