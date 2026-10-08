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
 * Renders the prompt preambles the attacker prepends to a chunk's user
 * message: deterministic pre-scan risk markers, the patterns already confirmed
 * by the reviewer in earlier iterations, the findings it rejected, and the
 * unverified candidates a cheaper first-pass model reported.
 */
final readonly class AttackerContextPromptRenderer
{
    private const int MAX_TITLE_LENGTH = 120;

    private const int MAX_LISTED_LOCATIONS = 100;

    /**
     * @param list<RiskMarker> $markers
     */
    public function renderRiskMarkers(array $markers): string
    {
        $byFile = [];
        foreach ($markers as $marker) {
            $byFile[$this->sanitizeLine($marker->filePath())][] = \sprintf(
                'L%d %s — %s',
                $marker->line(),
                $this->sanitizeLine($marker->pattern()),
                $this->sanitizeLine($marker->description()),
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
     * Each type with the locations of its findings, capped at
     * {@see self::MAX_LISTED_LOCATIONS} findings since every chunk of a
     * request carries the list.
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
     * A candidate title is a first-pass model's free text about untrusted code:
     * quoted so the deep pass reads it as data rather than as an instruction of
     * its own, with embedded double quotes folded so none can close the quote
     * early, and capped so a runaway title cannot crowd the prompt.
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
     * Risk-marker descriptions/patterns (e.g. imported SARIF `message.text`)
     * and file paths are attacker-influenced free text or come from the
     * audited (untrusted) codebase; an embedded line break could forge a fake
     * `##`-prefixed section as unguarded prompt text for the next attacker
     * call, so every such value is collapsed to a single line before it enters
     * the prompt. `\R` under `/u` covers every Unicode line break — CR, LF,
     * CRLF, VT, FF, NEL, LS and PS — where a plain `str_replace()` of CR and
     * LF would let the other five through.
     */
    private function sanitizeLine(string $value): string
    {
        $scrubbed = mb_scrub($value, 'UTF-8');

        return preg_replace('/\R/u', ' ', $scrubbed) ?? $scrubbed;
    }
}
