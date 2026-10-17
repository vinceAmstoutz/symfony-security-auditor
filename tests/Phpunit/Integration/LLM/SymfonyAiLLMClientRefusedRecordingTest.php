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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerScanCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedResultPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class SymfonyAiLLMClientRefusedRecordingTest extends TestCase
{
    private const string FILE = 'src/Controller/UserController.php';

    private const string REFUSED_NEVER_RECORDED = 'a finding the record tool refused was never recorded again';

    /**
     * @param list<ResultInterface> $rounds
     *
     * @throws BudgetExceededException
     * @throws InvalidProjectFileException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     */
    #[DataProvider('refusalsNoCallRepeats')]
    public function test_a_refused_finding_no_call_repeats_leaves_its_chunk_errored_and_uncached(array $rounds, int $maxToolIterations, int $maxConcurrent): void
    {
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($rounds, $maxToolIterations, $maxConcurrent, $attackerCache, $recordingCoverageRecorder);

        self::assertSame(['SQL injection in export()'], $this->titles($vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => self::FILE, 'status' => 'errored']], $recordingCoverageRecorder->coverage);
        self::assertSame([['stage' => 'attacker', 'filePath' => self::FILE, 'reason' => self::REFUSED_NEVER_RECORDED]], $recordingCoverageRecorder->failureReasons);
    }

    /** @return iterable<string, array{list<ResultInterface>, int, int}> */
    public static function refusalsNoCallRepeats(): iterable
    {
        $sibling = self::finding('SQL injection in export()', 40);
        $withoutLine = self::without(self::finding('SQL injection in search()', 12), 'line_start');
        $toolCallResult = self::callsOf($withoutLine, $sibling);

        yield 'a sibling of its type and file settles no refusal without a line' => [[$toolCallResult, new TextResult('Done.')], 8, 1];
        yield 'nor in the last round, which the recorded sibling concludes' => [[$toolCallResult], 1, 1];
        yield 'nor in a concurrent window' => [[$toolCallResult, new TextResult('Done.')], 8, 4];
        yield 'a sibling of its title at another line settles no refusal without a confidence' => [[self::callsOf(self::without(self::finding('SQL injection in export()', 12), 'confidence'), $sibling), new TextResult('Done.')], 8, 1];
        yield 'a sibling of another type settles no refusal' => [[self::callsOf($withoutLine, ['type' => 'xss'] + $sibling), new TextResult('Done.')], 8, 1];
    }

    /**
     * @param list<ResultInterface> $rounds
     *
     * @throws BudgetExceededException
     * @throws InvalidProjectFileException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     */
    #[DataProvider('refusalsTheModelRepeatsInFull')]
    public function test_a_refused_finding_the_model_makes_again_in_full_leaves_its_chunk_analyzed_and_cached(array $rounds, int $maxConcurrent): void
    {
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store');
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilities = $this->analyze($rounds, 8, $maxConcurrent, $attackerCache, $recordingCoverageRecorder);

        self::assertSame(['SQL injection in search()'], $this->titles($vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => self::FILE, 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
    }

    /** @return iterable<string, array{list<ResultInterface>, int}> */
    public static function refusalsTheModelRepeatsInFull(): iterable
    {
        $finding = self::finding('SQL injection in search()', 12);
        $inALaterAnswer = [self::callsOf(self::without($finding, 'line_start')), self::callsOf($finding), new TextResult('Done.')];
        $inTheSameAnswer = [self::callsOf(self::without($finding, 'confidence'), $finding), new TextResult('Done.')];

        yield 'in a later answer' => [$inALaterAnswer, 1];
        yield 'in a later answer of a concurrent window' => [$inALaterAnswer, 4];
        yield 'in the answer that held the refused call' => [$inTheSameAnswer, 1];
        yield 'in the answer that held the refused call, in a concurrent window' => [$inTheSameAnswer, 4];
    }

    /**
     * @param list<ResultInterface> $rounds
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws InvalidProjectFileException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     */
    private function analyze(array $rounds, int $maxToolIterations, int $maxConcurrent, AttackerCacheInterface $attackerCache, RecordingCoverageRecorder $recordingCoverageRecorder): array
    {
        $attackerAgent = new AttackerAgent(
            new AttackerLlmCollaborators(
                new SymfonyAiLLMClient(new PlatformBinding(new ScriptedResultPlatform($rounds), 'm', new NullLogger())),
                new AttackerPromptBuilder(),
                new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                new NullCodeSlicer(),
                new RecordVulnerabilityToolFactory(),
            ),
            new AttackerScanCollaborators($attackerCache, new NullStaticPreScanner(), new NullProgressReporter()),
            new AttackerAnalysisSettings(maxToolIterations: $maxToolIterations, maxConcurrent: $maxConcurrent),
            new NullLogger(),
        );

        return $attackerAgent->analyze(
            new AttackerAnalysisRequest([ProjectFile::create(self::FILE, '/app/'.self::FILE, "<?php\n")], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())),
            $recordingCoverageRecorder,
        );
    }

    /**
     * @param array<string, mixed> ...$findings
     */
    private static function callsOf(array ...$findings): ToolCallResult
    {
        $toolCalls = [];
        foreach (array_values($findings) as $position => $finding) {
            $toolCalls[] = new ToolCall((string) $position, 'record_vulnerability', $finding);
        }

        return new ToolCallResult($toolCalls);
    }

    /**
     * @return array<string, mixed>
     */
    private static function finding(string $title, int $lineStart): array
    {
        return [
            'type' => 'sql_injection',
            'severity' => 'high',
            'title' => $title,
            'description' => 'User input is concatenated into the DQL query.',
            'file_path' => self::FILE,
            'line_start' => $lineStart,
            'confidence' => 0.9,
        ];
    }

    /**
     * @param array<string, mixed> $finding
     *
     * @return array<string, mixed>
     */
    private static function without(array $finding, string $key): array
    {
        unset($finding[$key]);

        return $finding;
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     *
     * @return list<string>
     */
    private function titles(array $vulnerabilities): array
    {
        return array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities);
    }
}
