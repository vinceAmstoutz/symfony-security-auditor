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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Review;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\BatchVerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\OversizedReviewBatchRecovery;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class OversizedReviewBatchRecoveryTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_single_finding_the_model_cannot_fit_is_recorded_as_errored_without_another_call(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $calls = 0;

        $recovered = $this->recovery()->recover(
            [$this->vulnerabilityAt('src/A.php')],
            new LLMRequestTooLargeException('too large'),
            $recordingCoverageRecorder,
            static function (array $half) use (&$calls): array {
                ++$calls;

                return $half;
            },
        );

        self::assertCount(1, $recovered);
        self::assertFalse($recovered[0]->isReviewerValidated());
        self::assertSame(0, $calls);
        self::assertSame([['stage' => 'reviewer', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_batch_is_split_in_two_with_the_larger_half_first_and_each_half_reviewed_in_order(): void
    {
        $batch = [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php'), $this->vulnerabilityAt('src/C.php'), $this->vulnerabilityAt('src/D.php'), $this->vulnerabilityAt('src/E.php')];
        $halves = [];
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            'Reviewer batch exceeds the model input limit; it is split in two and each half reviewed on its own',
            ['batch_size' => 5, 'error' => 'too large'],
        );

        $recovered = $this->recovery($logger)->recover(
            $batch,
            new LLMRequestTooLargeException('too large'),
            new RecordingCoverageRecorder(),
            static function (array $half) use (&$halves): array {
                $halves[] = array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->filePath(), $half);

                return $half;
            },
        );

        self::assertSame([['src/A.php', 'src/B.php', 'src/C.php'], ['src/D.php', 'src/E.php']], $halves);
        self::assertSame($batch, $recovered);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_budget_abort_in_the_first_half_marks_the_second_half_aborted_and_propagates(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $calls = 0;

        $caught = null;
        try {
            $this->recovery()->recover(
                [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')],
                new LLMRequestTooLargeException('too large'),
                $recordingCoverageRecorder,
                static function () use (&$calls): array {
                    ++$calls;

                    throw BudgetExceededException::forTokens(10, 5);
                },
            );
        } catch (BudgetExceededException $budgetExceededException) {
            $caught = $budgetExceededException;
        }

        self::assertInstanceOf(BudgetExceededException::class, $caught);
        self::assertSame(1, $calls);
        self::assertSame([['stage' => 'reviewer', 'filePath' => 'src/B.php', 'status' => 'aborted']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     */
    public function test_a_provider_failure_in_the_first_half_marks_the_second_half_errored_and_propagates(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $caught = null;
        try {
            $this->recovery()->recover(
                [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')],
                new LLMRequestTooLargeException('too large'),
                $recordingCoverageRecorder,
                static fn (): array => throw new LLMProviderException('platform gone'),
            );
        } catch (LLMProviderException $llmProviderException) {
            $caught = $llmProviderException;
        }

        self::assertInstanceOf(LLMProviderException::class, $caught);
        self::assertSame('platform gone', $caught->getMessage());
        self::assertSame([['stage' => 'reviewer', 'filePath' => 'src/B.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     */
    public function test_a_failure_in_the_second_half_is_left_to_the_analyzer_that_reviewed_it(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $calls = 0;

        $caught = null;
        try {
            $this->recovery()->recover(
                [$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')],
                new LLMRequestTooLargeException('too large'),
                $recordingCoverageRecorder,
                static function (array $half) use (&$calls): array {
                    if (1 === ++$calls) {
                        return $half;
                    }

                    throw new LLMProviderException('platform gone');
                },
            );
        } catch (LLMProviderException $llmProviderException) {
            $caught = $llmProviderException;
        }

        self::assertInstanceOf(LLMProviderException::class, $caught);
        self::assertSame(2, $calls);
        self::assertSame([], $recordingCoverageRecorder->coverage);
    }

    private function recovery(?LoggerInterface $logger = null): OversizedReviewBatchRecovery
    {
        $reviewerVerdictCache = new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger());

        return new OversizedReviewBatchRecovery(
            new BatchVerdictApplier(new VerdictApplier(new NullLogger()), $reviewerVerdictCache, new NullLogger(), new NullProgressReporter()),
            $logger ?? new NullLogger(),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function vulnerabilityAt(string $filePath): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::HIGH, 'Test '.$filePath, 0.9),
            new CodeLocation($filePath, 1, 5),
            new VulnerabilityNarrative('Test', 'vec', 'proof', 'fix'),
            'code',
        );
    }
}
