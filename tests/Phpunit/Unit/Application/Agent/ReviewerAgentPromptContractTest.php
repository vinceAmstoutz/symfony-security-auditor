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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\PlainPromptRecordingLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\PromptLog;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ReviewerAgentHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\StubInvestigationTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ToolBatchPromptRecordingLLMClient;

final class ReviewerAgentPromptContractTest extends TestCase
{
    private const string FULL_WIRING = 'tool-batch client, both factories';

    private const string PLAIN_CLIENT = 'plain client, both factories';

    private const string NO_RECORD_REVIEW_FACTORY = 'tool-batch client, no record_review factory';

    private const string NO_INVESTIGATION_TOOLS = 'tool-batch client, no investigation tool factory';

    /**
     * @throws BudgetExceededException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws LLMProviderException
     */
    #[DataProvider('reviewModes')]
    public function test_the_prompt_asks_for_record_review_only_when_the_review_offers_that_tool(ReviewerModeConfiguration $reviewerModeConfiguration, string $wiring, bool $expectedRecordReview): void
    {
        $promptLog = new PromptLog();
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                self::PLAIN_CLIENT === $wiring ? new PlainPromptRecordingLLMClient($promptLog) : new ToolBatchPromptRecordingLLMClient($promptLog),
                new ReviewerPromptBuilder(useStructuredCollection: $reviewerModeConfiguration->useStructuredCollection),
                new NullLogger(),
                recordReviewToolFactory: self::NO_RECORD_REVIEW_FACTORY === $wiring ? null : new RecordReviewToolFactory(),
            ),
            $reviewerModeConfiguration,
            self::NO_INVESTIGATION_TOOLS === $wiring ? null : $this->investigationToolFactory(),
        );

        $reviewerAgent->review(ReviewerAgentHarness::vulnerabilitiesAt('src/A.php', 'src/B.php'), [], new NullCoverageRecorder());

        self::assertNotSame([], $promptLog->calls);
        foreach ($promptLog->calls as $call) {
            self::assertSame($expectedRecordReview, $call['offersRecordReview']);
            self::assertSame($expectedRecordReview, str_contains($call['prompt'], 'record_review'));
        }
    }

    /**
     * @return iterable<string, array{ReviewerModeConfiguration, string, bool}>
     */
    public static function reviewModes(): iterable
    {
        yield 'structured, one finding per call' => [new ReviewerModeConfiguration(), self::FULL_WIRING, true];
        yield 'structured, batched' => [new ReviewerModeConfiguration(batchSize: 2), self::FULL_WIRING, true];
        yield 'structured, concurrent on a tool-batch client' => [new ReviewerModeConfiguration(maxConcurrent: 4), self::FULL_WIRING, true];
        yield 'structured, sequential on a plain client' => [new ReviewerModeConfiguration(), self::PLAIN_CLIENT, true];
        yield 'structured, batched, concurrency requested on a plain client' => [new ReviewerModeConfiguration(batchSize: 2, maxConcurrent: 4), self::PLAIN_CLIENT, true];
        yield 'structured, concurrency of two requested on a plain client' => [new ReviewerModeConfiguration(maxConcurrent: 2), self::PLAIN_CLIENT, false];
        yield 'structured, concurrency requested on a plain client' => [new ReviewerModeConfiguration(maxConcurrent: 4), self::PLAIN_CLIENT, false];
        yield 'structured without a record_review factory' => [new ReviewerModeConfiguration(), self::NO_RECORD_REVIEW_FACTORY, false];
        yield 'structured, tools requested without an investigation tool factory' => [new ReviewerModeConfiguration(toolsEnabled: true), self::NO_INVESTIGATION_TOOLS, true];
        yield 'structured with tools, one finding per call' => [new ReviewerModeConfiguration(toolsEnabled: true), self::FULL_WIRING, false];
        yield 'structured with tools, batched' => [new ReviewerModeConfiguration(batchSize: 2, toolsEnabled: true), self::FULL_WIRING, false];
        yield 'structured with tools, concurrent' => [new ReviewerModeConfiguration(toolsEnabled: true, maxConcurrent: 4), self::FULL_WIRING, false];
        yield 'structured with tools on a plain client' => [new ReviewerModeConfiguration(toolsEnabled: true), self::PLAIN_CLIENT, false];
        yield 'json, one finding per call' => [new ReviewerModeConfiguration(useStructuredCollection: false), self::FULL_WIRING, false];
        yield 'json, batched' => [new ReviewerModeConfiguration(batchSize: 2, useStructuredCollection: false), self::FULL_WIRING, false];
        yield 'json, concurrent' => [new ReviewerModeConfiguration(maxConcurrent: 4, useStructuredCollection: false), self::FULL_WIRING, false];
        yield 'json with tools' => [new ReviewerModeConfiguration(toolsEnabled: true, useStructuredCollection: false), self::FULL_WIRING, false];
        yield 'json with tools, batched, on a plain client' => [new ReviewerModeConfiguration(batchSize: 2, toolsEnabled: true, useStructuredCollection: false), self::PLAIN_CLIENT, false];
    }

    /**
     * @throws InvalidToolRegistryException
     */
    private function investigationToolFactory(): ToolRegistryFactoryInterface
    {
        $toolFactory = self::createStub(ToolRegistryFactoryInterface::class);
        $toolFactory->method('forProjectFiles')->willReturn(new ToolRegistry([new StubInvestigationTool()], new NullLogger()));

        return $toolFactory;
    }
}
