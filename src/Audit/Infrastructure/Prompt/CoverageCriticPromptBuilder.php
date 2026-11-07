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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CoverageCriticPromptBuilderInterface;

/**
 * The coverage critic's prompts: what a gap is, and a summary of the audit —
 * the routes and their guards, the voters, the file groups the attacker
 * analyzed with each file's coverage status, and the findings so far. No
 * file's contents ever reach it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CoverageCriticPromptBuilder implements CoverageCriticPromptBuilderInterface
{
    private const int MAX_LISTED_GROUPS = 200;

    private const int MAX_LISTED_FINDINGS = 100;

    private const int MAX_TITLE_LENGTH = 120;

    private const string RECORD_INSTRUCTION = 'Record each gap with one `record_coverage_gap` call: `files` (the paths to analyze together), `hypothesis` (what they may let an attacker do, in one or two sentences) and `attack_class` (a finding type such as broken_access_control). Do not answer with prose or JSON.';

    private const string JSON_INSTRUCTION = 'Answer with ONLY a JSON array of gap objects, each `{"files": [the paths to analyze together], "hypothesis": "what they may let an attacker do, in one or two sentences", "attack_class": "a finding type such as broken_access_control"}` — no prose, no markdown fences. Answer `[]` when there is no gap.';

    #[Override]
    public function buildSystemPrompt(int $maxGaps, bool $structuredCollection): string
    {
        $outputInstruction = $structuredCollection ? self::RECORD_INSTRUCTION : self::JSON_INSTRUCTION;

        return <<<PROMPT
            You are the coverage critic of a security audit of a Symfony application. An attacker model has already audited the project chunk by chunk: each chunk showed it one group of files, so a weakness that spans two groups may never have been examined — an entry point never shown with its handler; a bulk, import or export path that lacks the check its single-item path has; a console command or a Messenger message reaching the same handler as a guarded route.

            From the summary below — never source code — name at most {$maxGaps} gaps: files that were never examined together and may, together, expose a vulnerability. Name only files the summary lists, by the exact path it gives. Name no gap when the coverage looks complete; never invent one to reach the limit.

            {$outputInstruction}
            PROMPT;
    }

    #[Override]
    public function buildUserMessage(SymfonyMapping $symfonyMapping, array $fileGroups, AuditContext $auditContext): string
    {
        return implode('', [
            SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping),
            SymfonyMappingContextRenderer::renderVoterCoverage($symfonyMapping),
            $this->renderFileGroups($fileGroups, $auditContext),
            $this->renderConfirmedFindings($auditContext),
        ]);
    }

    /**
     * @param list<list<ProjectFile>> $fileGroups
     */
    private function renderFileGroups(array $fileGroups, AuditContext $auditContext): string
    {
        $statuses = $this->lastAttackerStatuses($auditContext);
        $groupLines = array_map(
            fn (array $fileGroup): string => \sprintf('- %s', implode(', ', array_map(
                fn (ProjectFile $projectFile): string => \sprintf('%s (%s)', $this->singleLine($projectFile->relativePath()), $statuses[$projectFile->relativePath()] ?? 'not analyzed'),
                $fileGroup,
            ))),
            $fileGroups,
        );

        return \sprintf(
            "## File Groups the Attacker Analyzed\nEach line is one group of files the attacker saw together in a single chunk, each file with its coverage status: analyzed, cached, skipped (left out by the lean pre-scan), errored or aborted.\n%s\n\n",
            implode("\n", $this->capped($groupLines, self::MAX_LISTED_GROUPS, 'group')),
        );
    }

    private function renderConfirmedFindings(AuditContext $auditContext): string
    {
        $findingLines = array_map(
            fn (Vulnerability $vulnerability): string => \sprintf('- %s: %s — %s', $vulnerability->type()->value, $this->singleLine($vulnerability->filePath()), $this->quotedTitle($vulnerability->title())),
            array_values($auditContext->validatedVulnerabilities()),
        );

        return \sprintf("## Findings Confirmed So Far\n%s\n", implode("\n", [] === $findingLines ? ['- none'] : $this->capped($findingLines, self::MAX_LISTED_FINDINGS, 'finding')));
    }

    /**
     * @param list<string> $lines
     *
     * @return list<string> the first lines up to the cap, then how many more are not listed
     */
    private function capped(array $lines, int $maxListed, string $noun): array
    {
        $listed = \array_slice($lines, 0, $maxListed);
        $notListed = \count($lines) - $maxListed;
        if ($notListed > 0) {
            $listed[] = \sprintf('- … and %d more %s%s not listed', $notListed, $noun, 1 === $notListed ? '' : 's');
        }

        return $listed;
    }

    /**
     * A title is a model's free text: quoted with its own double quotes folded
     * so none closes the quote early, and capped so a runaway one cannot crowd
     * the summary.
     */
    private function quotedTitle(string $title): string
    {
        $singleLine = str_replace('"', "'", $this->singleLine($title));

        if (mb_strlen($singleLine, 'UTF-8') > self::MAX_TITLE_LENGTH) {
            $singleLine = \sprintf('%s…', mb_substr($singleLine, 0, self::MAX_TITLE_LENGTH, 'UTF-8'));
        }

        return \sprintf('"%s"', $singleLine);
    }

    /**
     * A path or a title is text from the audited code or a model: a line break
     * in it would open a section of its own in the prompt.
     */
    private function singleLine(string $value): string
    {
        $scrubbed = mb_scrub($value, 'UTF-8');

        return preg_replace('/\R/u', ' ', $scrubbed) ?? $scrubbed;
    }

    /**
     * @return array<string, string> the attacker's last status of each file, as the coverage ledger records it
     */
    private function lastAttackerStatuses(AuditContext $auditContext): array
    {
        $statuses = [];
        foreach ($auditContext->coverage() as $entry) {
            if (AgentRole::Attacker->value === $entry['stage']) {
                $statuses[$entry['file']] = $entry['status'];
            }
        }

        return $statuses;
    }
}
