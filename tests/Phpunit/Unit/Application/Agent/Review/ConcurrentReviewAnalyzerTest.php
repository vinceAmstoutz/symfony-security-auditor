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
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ConcurrentReviewAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewOutcomeRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

final class ConcurrentReviewAnalyzerTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_it_dispatches_one_request_per_window_when_max_concurrent_is_one(): void
    {
        $batchSizes = [];
        $llmClient = self::createStub(BatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatch')->willReturnCallback(
            static function (array $requests) use (&$batchSizes): array {
                $batchSizes[] = \count($requests);

                return array_map(
                    static fn (): LLMResponse => LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
                    $requests,
                );
            },
        );

        $analyzer = new ConcurrentReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            $this->reviewOutcomeRecorder(),
            1,
        );

        $analyzer->analyze([$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')], [], new NullCoverageRecorder(), false);

        self::assertSame([1, 1], $batchSizes);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_it_accumulates_verdicts_across_every_window(): void
    {
        $vulnerabilities = [
            $this->vulnerabilityAt('src/A.php'),
            $this->vulnerabilityAt('src/B.php'),
            $this->vulnerabilityAt('src/C.php'),
            $this->vulnerabilityAt('src/D.php'),
        ];

        $llmClient = self::createStub(BatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatch')->willReturnCallback(
            static fn (array $requests): array => array_map(
                static fn (): LLMResponse => LLMResponse::of('{"accepted": true}', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)),
                $requests,
            ),
        );

        $analyzer = new ConcurrentReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            $this->reviewOutcomeRecorder(),
            2,
        );

        $reviewed = $analyzer->analyze($vulnerabilities, [], new NullCoverageRecorder(), false);

        self::assertSame(
            ['src/A.php', 'src/B.php', 'src/C.php', 'src/D.php'],
            array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->filePath(), $reviewed),
        );
    }

    private function reviewOutcomeRecorder(): ReviewOutcomeRecorder
    {
        return new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            new NullProgressReporter(),
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
