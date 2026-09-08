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
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\Review\ConcurrentStructuredReviewAnalyzer;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\Review\ReviewOutcomeRecorder;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;
use VinceAmstoutz\SecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

final class ConcurrentStructuredReviewAnalyzerTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_it_dispatches_one_request_per_window_when_max_concurrent_is_one(): void
    {
        $batchSizes = [];
        $llmClient = self::createStub(ToolBatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatchWithTools')->willReturnCallback(
            static function (array $requests) use (&$batchSizes): array {
                $batchSizes[] = \count($requests);

                return array_fill(0, \count($requests), LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(1, 1)));
            },
        );

        $concurrentStructuredReviewAnalyzer = new ConcurrentStructuredReviewAnalyzer(
            $llmClient,
            new ReviewerPromptBuilder(useStructuredCollection: true),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            $this->reviewOutcomeRecorder(),
            new RecordReviewToolFactory(),
            new NullLogger(),
            1,
            4,
        );

        $concurrentStructuredReviewAnalyzer->analyze([$this->vulnerabilityAt('src/A.php'), $this->vulnerabilityAt('src/B.php')], [], new NullCoverageRecorder(), false);

        self::assertSame([1, 1], $batchSizes);
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
