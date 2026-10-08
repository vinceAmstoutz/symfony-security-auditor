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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\SequentialChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\InvalidCustomRiskPatternException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\SequentialChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class SequentialChunkAnalyzerSplitChunkTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return ChunkAnalysisInputs::file($path);
    }

    private function analyzer(LLMClientInterface $llmClient, AttackerCacheInterface $attackerCache, bool $structured, ?LoggerInterface $logger = null): SequentialChunkAnalyzer
    {
        return SequentialChunkAnalyzerHarness::analyzer($llmClient, $attackerCache, $structured, $logger);
    }

    private function request(): AttackerAnalysisRequest
    {
        return ChunkAnalysisInputs::request();
    }

    /**
     * @return array<string, mixed>
     */
    private static function finding(string $title): array
    {
        return SequentialChunkAnalyzerHarness::finding($title);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_chunk_the_model_cannot_fit_is_split_in_two_and_each_half_analyzed_on_its_own(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            $files = array_values(array_filter(['src/A.php', 'src/B.php', 'src/C.php'], static fn (string $file): bool => str_contains($user, $file)));
            if (3 === \count($files)) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer('from '.implode('+', $files));
        });
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Attacker chunk exceeds the model input limit; it is split in two and each half analyzed on its own',
            ['files' => ['src/A.php', 'src/B.php', 'src/C.php'], 'error' => 'prompt is too long'],
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, new NullAttackerCache(), false, $logger)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php'), $this->makeFile('src/C.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from src/A.php+src/B.php', 'from src/C.php'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/C.php', 'status' => 'analyzed'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws InvalidRiskMarkerException
     * @throws InvalidCustomRiskPatternException
     */
    public function test_a_file_the_pre_scanner_flags_on_every_line_is_analyzed_instead_of_stopping_the_run(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/FloodController.php',
            '/app/src/Controller/FloodController.php',
            "<?php\nclass FloodController extends AbstractController\n{\n".str_repeat("\$request->x;\n", 8000)."}\n",
        );
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (\strlen($system) + \strlen($user) > 800_000) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer('from the flooded file');
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, new NullAttackerCache(), false)->analyze(
            [[$projectFile]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex((new RegexStaticPreScanner())->scan([$projectFile])),
        );

        self::assertSame(['from the flooded file'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/Controller/FloodController.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_half_of_a_split_chunk_already_in_the_cache_is_served_without_a_provider_call(): void
    {
        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::exactly(2))->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/B.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer('from A');
        });
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturnCallback(
            static fn (array $chunk): ?array => 1 === \count($chunk) && $chunk[0] instanceof ProjectFile && 'src/B.php' === $chunk[0]->relativePath() ? [self::finding('cached B')] : null,
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from A', 'cached B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'cached'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_the_findings_of_both_halves_are_cached_under_the_whole_chunk_so_the_next_run_does_not_send_it_again(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/B.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer(str_contains($user, 'src/A.php') ? 'from A' : 'from B');
        });
        $stored = [];
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->method('store')->willReturnCallback(static function (array $chunk, array $rawVulnerabilities) use (&$stored): void {
            $stored[] = [self::pathsOf($chunk), array_column($rawVulnerabilities, 'title', 'file_path')];
        });

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            $this->request(),
            new RecordingCoverageRecorder(),
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from A', 'from B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                [['src/A.php'], ['src/A.php' => 'from A']],
                [['src/B.php'], ['src/A.php' => 'from B']],
                [['src/A.php', 'src/B.php'], ['src/A.php' => 'from B']],
            ],
            $stored,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_split_chunk_is_not_cached_whole_when_caching_is_bypassed(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/B.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            return self::jsonAnswer(str_contains($user, 'src/A.php') ? 'from A' : 'from B');
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::never())->method('store');

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), true),
            new RecordingCoverageRecorder(),
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from A', 'from B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    public function test_a_split_chunk_is_not_cached_whole_when_a_half_came_back_cut_short(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/B.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            if (str_contains($user, 'src/B.php')) {
                return LLMResponse::of((string) json_encode([self::finding('from B')]), 'm', 'length', TokenUsageSnapshot::of(1, 1));
            }

            return self::jsonAnswer('from A');
        });
        $attackerCache = $this->createMock(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturn(null);
        $attackerCache->expects(self::once())->method('store')->with(
            self::callback(static fn (array $chunk): bool => 1 === \count($chunk) && $chunk[0] instanceof ProjectFile && 'src/A.php' === $chunk[0]->relativePath()),
            self::anything(),
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->analyzer($llmClient, $attackerCache, false)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['from A', 'from B'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'errored'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_the_findings_of_a_cached_half_are_recorded_when_the_cache_serves_it(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user): LLMResponse {
            throw new LLMRequestTooLargeException('prompt is too long');
        });
        $attackerCache = self::createStub(AttackerCacheInterface::class);
        $attackerCache->method('get')->willReturnCallback(
            static fn (array $chunk): ?array => 1 === \count($chunk) ? [self::finding('cached '.self::pathsOf($chunk)[0])] : null,
        );
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $this->analyzer($llmClient, $attackerCache, false)->analyze(
            [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex([]),
        );

        self::assertSame(['cached src/A.php', 'cached src/B.php'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $recordingCoverageRecorder->found));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('abortsOfTheSecondHalf')]
    public function test_the_findings_of_the_first_half_survive_an_abort_in_the_second_half(Throwable $throwable): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user) use ($throwable): LLMResponse {
            if (str_contains($user, 'src/A.php') && str_contains($user, 'src/B.php')) {
                throw new LLMRequestTooLargeException('prompt is too long');
            }

            if (str_contains($user, 'src/A.php')) {
                return self::jsonAnswer('from A');
            }

            throw $throwable;
        });
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $caught = null;

        try {
            $this->analyzer($llmClient, new NullAttackerCache(), false)->analyze(
                [[$this->makeFile('src/A.php'), $this->makeFile('src/B.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                null,
                new RiskMarkerIndex([]),
            );
        } catch (BudgetExceededException|LLMProviderException $exception) {
            $caught = $exception;
        }

        self::assertSame($throwable, $caught);
        self::assertSame(['from A'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $recordingCoverageRecorder->drainFoundVulnerabilities()));
    }

    /**
     * @return iterable<string, array{Throwable}>
     */
    public static function abortsOfTheSecondHalf(): iterable
    {
        yield 'a budget abort' => [BudgetExceededException::forTokens(150, 100)];
        yield 'a provider abort' => [new LLMProviderException('platform gone')];
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private static function jsonAnswer(string $title): LLMResponse
    {
        return SequentialChunkAnalyzerHarness::jsonAnswer($title);
    }

    /**
     * @return list<string>
     */
    private static function pathsOf(mixed $chunk): array
    {
        self::assertIsArray($chunk);
        $paths = [];
        foreach ($chunk as $file) {
            self::assertInstanceOf(ProjectFile::class, $file);
            $paths[] = $file->relativePath();
        }

        return $paths;
    }
}
