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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\ErrorHandler\BufferingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EscalatingAttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingAttackerAgent;

final class EscalatingAttackerAgentTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_skips_expensive_pass_when_cheap_finds_nothing(): void
    {
        $recordingAttackerAgent = $this->makeRecordingAttacker([]);
        $expensive = $this->makeRecordingAttacker([]);

        $escalatingAttackerAgent = new EscalatingAttackerAgent($recordingAttackerAgent, $expensive, new NullLogger());

        $result = $this->callAnalyze($escalatingAttackerAgent,
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        self::assertSame([], $result);
        self::assertSame(1, $recordingAttackerAgent->callCount);
        self::assertSame(0, $expensive->callCount);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_cheap_findings_survive_an_expensive_pass_abort(): void
    {
        $vulnerability = $this->makeVulnerability('src/Controller/A.php', title: 'cheap');
        $recordingAttackerAgent = $this->makeRecordingAttacker([$vulnerability]);
        $expensive = new RecordingAttackerAgent([], BudgetExceededException::forTokens(500, 100));

        $escalatingAttackerAgent = new EscalatingAttackerAgent($recordingAttackerAgent, $expensive, new NullLogger());
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        $budgetExceeded = false;
        try {
            $this->callAnalyze($escalatingAttackerAgent,
                [$this->makeFile('src/Controller/A.php')],
                SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
                $auditContext,
            );
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The escalating agent must rethrow BudgetExceededException.');
        self::assertSame([$vulnerability], $auditContext->drainFoundVulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_runs_expensive_pass_only_on_files_flagged_by_cheap(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
            $this->makeFile('src/Controller/C.php'),
        ];

        $recordingAttackerAgent = $this->makeRecordingAttacker([
            $this->makeVulnerability('src/Controller/A.php'),
        ]);
        $expensive = $this->makeRecordingAttacker([]);

        $escalatingAttackerAgent = new EscalatingAttackerAgent($recordingAttackerAgent, $expensive, new NullLogger());

        $this->callAnalyze($escalatingAttackerAgent, $files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), new NullCoverageRecorder());

        self::assertSame(1, $expensive->callCount);
        self::assertCount(1, $expensive->lastFiles);
        self::assertSame('src/Controller/A.php', $expensive->lastFiles[0]->relativePath());
    }

    /**
     * @param ?list<string> $toolPaths
     * @param list<string>  $expectedToolPaths
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('toolScopes')]
    public function test_the_deep_pass_analyzes_the_flagged_files_but_its_tools_keep_the_reach_of_the_request(?array $toolPaths, array $expectedToolPaths): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
            $this->makeFile('src/Controller/C.php'),
        ];
        $toolFiles = null === $toolPaths ? null : array_map($this->makeFile(...), $toolPaths);
        $recordingAttackerAgent = $this->makeRecordingAttacker([]);
        $escalatingAttackerAgent = new EscalatingAttackerAgent(
            $this->makeRecordingAttacker([$this->makeVulnerability('src/Controller/A.php')]),
            $recordingAttackerAgent,
            new NullLogger(),
        );

        $escalatingAttackerAgent->analyze(
            new AttackerAnalysisRequest($files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), toolFiles: $toolFiles),
            new NullCoverageRecorder(),
        );

        self::assertSame(['src/Controller/A.php'], array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $recordingAttackerAgent->lastFiles));
        self::assertSame($expectedToolPaths, array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $recordingAttackerAgent->lastToolFiles));
    }

    /**
     * @return iterable<string, array{?list<string>, list<string>}>
     */
    public static function toolScopes(): iterable
    {
        yield 'wider than the files to analyze' => [
            ['src/Controller/A.php', 'src/Controller/B.php', 'src/Controller/C.php', 'src/Service/Clean.php'],
            ['src/Controller/A.php', 'src/Controller/B.php', 'src/Controller/C.php', 'src/Service/Clean.php'],
        ];
        yield 'not given, so the files to analyze' => [null, ['src/Controller/A.php', 'src/Controller/B.php', 'src/Controller/C.php']];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_expensive_findings_supersede_cheap_findings_on_overlap(): void
    {
        $vulnerability = $this->makeVulnerability(
            'src/Controller/A.php',
            VulnerabilitySeverity::MEDIUM,
            title: 'cheap version',
        );
        $expensiveVuln = $this->makeVulnerability(
            'src/Controller/A.php',
            VulnerabilitySeverity::HIGH,
            title: 'expensive version',
        );

        $recordingAttackerAgent = $this->makeRecordingAttacker([$vulnerability]);
        $expensive = $this->makeRecordingAttacker([$expensiveVuln]);

        $escalatingAttackerAgent = new EscalatingAttackerAgent($recordingAttackerAgent, $expensive, new NullLogger());

        $result = $this->callAnalyze($escalatingAttackerAgent,
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        self::assertCount(1, $result);
        self::assertSame('expensive version', $result[0]->title());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_cheap_findings_on_files_expensive_did_not_re_flag_are_kept(): void
    {
        $cheapOnA = $this->makeVulnerability('src/Controller/A.php', title: 'cheap A');
        $cheapOnB = $this->makeVulnerability('src/Controller/B.php', title: 'cheap B');
        $expensiveOnA = $this->makeVulnerability('src/Controller/A.php', title: 'expensive A');

        $recordingAttackerAgent = $this->makeRecordingAttacker([$cheapOnA, $cheapOnB]);
        $expensive = $this->makeRecordingAttacker([$expensiveOnA]);

        $escalatingAttackerAgent = new EscalatingAttackerAgent($recordingAttackerAgent, $expensive, new NullLogger());

        $result = $this->callAnalyze($escalatingAttackerAgent,
            [$this->makeFile('src/Controller/A.php'), $this->makeFile('src/Controller/B.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        $titles = array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $result);
        self::assertContains('expensive A', $titles);
        self::assertContains('cheap B', $titles);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_expensive_pass_receives_cheap_findings_as_unverified_candidates_not_as_confirmed_patterns(): void
    {
        $vulnerability = $this->makeVulnerability('src/Controller/A.php');

        $recordingAttackerAgent = $this->makeRecordingAttacker([$vulnerability]);
        $expensive = $this->makeRecordingAttacker([]);

        $escalatingAttackerAgent = new EscalatingAttackerAgent($recordingAttackerAgent, $expensive, new NullLogger());

        $this->callAnalyze($escalatingAttackerAgent,
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        self::assertSame([$vulnerability], $expensive->lastCandidateFindings);
        self::assertSame([], $expensive->lastPreviousFindings);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_logs_file_counts_for_both_passes(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
            $this->makeFile('src/Controller/C.php'),
        ];
        $recordingAttackerAgent = $this->makeRecordingAttacker([$this->makeVulnerability('src/Controller/A.php')]);
        $expensive = $this->makeRecordingAttacker([]);
        $bufferingLogger = new BufferingLogger();

        (new EscalatingAttackerAgent($recordingAttackerAgent, $expensive, $bufferingLogger))
            ->analyze(new AttackerAnalysisRequest($files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())), new NullCoverageRecorder());

        $logs = $bufferingLogger->cleanLogs();
        self::assertSame(['files' => 3], $this->contextOf($logs, 'Escalation: running cheap-model first pass'));
        self::assertSame(
            ['cheap_findings' => 1, 'hot_files' => 1, 'cold_files_skipped' => 2],
            $this->contextOf($logs, 'Escalation: running expensive-model deep pass on hot files'),
        );
    }

    /**
     * `Vulnerability::filePath()` is free text echoed back by the LLM — the
     * schema only constrains it to a non-blank string, so a cheap-model
     * quirk like a leading `./` (a plausible path-normalization artifact) is
     * never enforced to exactly match `ProjectFile::relativePath()`. Without
     * normalizing both sides before comparing, the file with a real cheap
     * finding is silently excluded from the expensive pass — the escalation
     * feature quietly no-ops for it, indistinguishable from "nothing needed
     * escalating".
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_escalates_a_file_whose_cheap_finding_path_has_a_leading_dot_slash(): void
    {
        $vulnerability = $this->makeVulnerability('./src/Controller/A.php');
        $recordingAttackerAgent = $this->makeRecordingAttacker([$vulnerability]);
        $expensive = $this->makeRecordingAttacker([]);

        $this->callAnalyze(
            new EscalatingAttackerAgent($recordingAttackerAgent, $expensive, new NullLogger()),
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        self::assertCount(1, $expensive->lastFiles);
        self::assertSame('src/Controller/A.php', $expensive->lastFiles[0]->relativePath());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_logs_when_cheap_pass_finds_nothing(): void
    {
        $bufferingLogger = new BufferingLogger();

        (new EscalatingAttackerAgent($this->makeRecordingAttacker([]), $this->makeRecordingAttacker([]), $bufferingLogger))
            ->analyze(new AttackerAnalysisRequest([$this->makeFile('src/Controller/A.php')], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())), new NullCoverageRecorder());

        self::assertSame([], $this->contextOf($bufferingLogger->cleanLogs(), 'Escalation: cheap pass found nothing, skipping expensive pass'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_expensive_pass_keeps_the_original_previous_findings_and_receives_every_cheap_finding_as_a_candidate(): void
    {
        $previous = [$this->makeVulnerability('src/Controller/Z.php', title: 'prev')];
        $recordingAttackerAgent = $this->makeRecordingAttacker([
            $this->makeVulnerability('src/Controller/A.php', title: 'cheapA'),
            $this->makeVulnerability('src/Controller/B.php', title: 'cheapB'),
        ]);
        $expensive = $this->makeRecordingAttacker([]);

        (new EscalatingAttackerAgent($recordingAttackerAgent, $expensive, new NullLogger()))->analyze(
            new AttackerAnalysisRequest(
                [$this->makeFile('src/Controller/A.php'), $this->makeFile('src/Controller/B.php')],
                SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
                false,
                $previous,
            ),
            new NullCoverageRecorder(),
        );

        self::assertSame($previous, $expensive->lastPreviousFindings);
        self::assertSame(['cheapA', 'cheapB'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $expensive->lastCandidateFindings));
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<Vulnerability>
     */
    private function callAnalyze(AttackerAgentInterface $attackerAgent, array $files, SymfonyMapping $symfonyMapping, CoverageRecorderInterface $coverageRecorder): array
    {
        return $attackerAgent->analyze(new AttackerAnalysisRequest($files, $symfonyMapping), $coverageRecorder);
    }

    /**
     * @param array<mixed> $logs
     *
     * @return array<mixed>
     */
    private function contextOf(array $logs, string $message): array
    {
        foreach ($logs as $log) {
            self::assertIsArray($log);
            if ($message === ($log[1] ?? null)) {
                $context = $log[2] ?? [];
                self::assertIsArray($context);

                return $context;
            }
        }

        self::fail(\sprintf('No log entry with message "%s"', $message));
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerability(
        string $filePath,
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
        string $title = 'v',
    ): Vulnerability {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, $vulnerabilitySeverity, $title, 0.9),
            new CodeLocation($filePath, 10, 15),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }

    /**
     * @param list<Vulnerability> $returnedFindings
     */
    private function makeRecordingAttacker(array $returnedFindings): RecordingAttackerAgent
    {
        return new RecordingAttackerAgent($returnedFindings);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('judgedStatuses')]
    public function test_a_cheap_finding_the_deep_pass_did_not_re_report_on_a_file_it_judged_is_discarded(string $status): void
    {
        $recordingAttackerAgent = $this->makeRecordingAttacker([$this->makeVulnerability('src/Controller/A.php', title: 'cheap A')]);
        $expensive = new RecordingAttackerAgent([], coverageStatus: $status);

        $result = $this->callAnalyze(
            new EscalatingAttackerAgent($recordingAttackerAgent, $expensive, new NullLogger()),
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        self::assertSame([], $result);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function judgedStatuses(): iterable
    {
        yield 'analyzed by the deep pass' => ['analyzed'];
        yield 'served from the deep pass cache' => ['cached'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidAuditContextException
     */
    public function test_only_the_findings_it_did_not_discard_are_left_to_recover_after_the_pass(): void
    {
        $vulnerability = $this->makeVulnerability('src/Controller/A.php', title: 'cheap A');
        $notJudged = $this->makeVulnerability('src/Controller/Other.php', title: 'cheap other');
        $deepReturned = $this->makeVulnerability('src/Controller/A.php', VulnerabilitySeverity::CRITICAL, 'deep A');
        $deepRecordedOnly = $this->makeVulnerability('src/Controller/A.php', VulnerabilitySeverity::LOW, 'deep partial');
        $recordingAttackerAgent = new RecordingAttackerAgent([$deepReturned], null, [$deepRecordedOnly], 'analyzed');
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        $this->callAnalyze(
            new EscalatingAttackerAgent($this->makeRecordingAttacker([$vulnerability, $notJudged]), $recordingAttackerAgent, new NullLogger()),
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            $auditContext,
        );

        self::assertSame([$notJudged, $deepReturned, $deepRecordedOnly], $auditContext->drainFoundVulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidAuditContextException
     */
    public function test_a_finding_the_deep_pass_recorded_stays_recoverable_even_when_it_equals_a_discarded_one(): void
    {
        $vulnerability = $this->makeVulnerability('src/Controller/A.php', title: 'cheap A');
        $twin = $vulnerability->withReviewerValidation(false);
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        $this->callAnalyze(
            new EscalatingAttackerAgent($this->makeRecordingAttacker([$vulnerability]), new RecordingAttackerAgent([], null, [$twin], 'analyzed'), new NullLogger()),
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            $auditContext,
        );

        self::assertSame([$twin], $auditContext->drainFoundVulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidAuditContextException
     */
    public function test_a_cheap_finding_is_judged_only_by_the_exact_file_the_deep_pass_analyzed(): void
    {
        $vulnerability = $this->makeVulnerability('1.0', title: 'judged');
        $loosely = $this->makeVulnerability('1.00', title: 'loosely equal path');
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        $result = $this->callAnalyze(
            new EscalatingAttackerAgent($this->makeRecordingAttacker([$vulnerability, $loosely]), new RecordingAttackerAgent([], coverageStatus: 'analyzed'), new NullLogger()),
            [$this->makeFile('1.0')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            $auditContext,
        );

        self::assertSame([$loosely], $result);
        self::assertSame([$loosely], $auditContext->drainFoundVulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_cheap_finding_on_a_file_the_deep_pass_errored_on_is_kept(): void
    {
        $vulnerability = $this->makeVulnerability('src/Controller/A.php', title: 'cheap A');
        $recordingAttackerAgent = new RecordingAttackerAgent([], coverageStatus: 'errored');

        $result = $this->callAnalyze(
            new EscalatingAttackerAgent($this->makeRecordingAttacker([$vulnerability]), $recordingAttackerAgent, new NullLogger()),
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        self::assertSame([$vulnerability], $result);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_candidate_the_deep_pass_refined_to_other_lines_replaces_the_cheap_finding_instead_of_doubling_it(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'refined A', 0.9),
            new CodeLocation('src/Controller/A.php', 12, 15),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
        $recordingAttackerAgent = new RecordingAttackerAgent([$vulnerability], coverageStatus: 'analyzed');

        $result = $this->callAnalyze(
            new EscalatingAttackerAgent($this->makeRecordingAttacker([$this->makeVulnerability('src/Controller/A.php', title: 'cheap A')]), $recordingAttackerAgent, new NullLogger()),
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        self::assertSame([$vulnerability], $result);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_cheap_finding_whose_path_carries_a_leading_dot_slash_is_matched_to_the_file_the_deep_pass_judged(): void
    {
        $recordingAttackerAgent = new RecordingAttackerAgent([], coverageStatus: 'analyzed');

        $result = $this->callAnalyze(
            new EscalatingAttackerAgent($this->makeRecordingAttacker([$this->makeVulnerability('./src/Controller/A.php', title: 'cheap A')]), $recordingAttackerAgent, new NullLogger()),
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            new NullCoverageRecorder(),
        );

        self::assertSame([], $result);
    }
}
