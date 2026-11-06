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

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\Exception\MaxOutputTokensException;
use Symfony\AI\Platform\PlatformOptions;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\StructuredVulnerabilityCollectionSession;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\MessageCollectingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedTokenUsagePlatform;

final class SymfonyAiLLMClientOutputCapRaiseTest extends TestCase
{
    /**
     * @throws LLMProviderException
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_a_tool_call_cut_off_by_the_output_cap_is_asked_again_once_with_twice_the_cap(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off'), new TextResult('done')], [new TokenUsage(), new TokenUsage()]);

        $llmResponse = $this->client($scriptedTokenUsagePlatform)->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame('done', $llmResponse->content());
        self::assertSame([4096, 8192], array_column($scriptedTokenUsagePlatform->invokedOptions, PlatformOptions::MAX_OUTPUT_TOKENS));
    }

    /**
     * @throws LLMProviderException
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_a_tool_call_the_raised_cap_still_cuts_off_ends_as_a_length_response(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off'), new MaxOutputTokensException('cut off again')], [new TokenUsage(), new TokenUsage()]);

        $llmResponse = $this->client($scriptedTokenUsagePlatform)->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame(['length', 2], [$llmResponse->stopReason(), $scriptedTokenUsagePlatform->invocations]);
    }

    /**
     * @throws LLMProviderException
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidRetryConfigurationException
     */
    public function test_an_answer_without_tools_cut_off_by_the_output_cap_is_not_asked_again(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off'), new TextResult('done')], [new TokenUsage(), new TokenUsage()]);

        $llmResponse = $this->client($scriptedTokenUsagePlatform)->complete('sys', 'usr');

        self::assertSame(['length', 1], [$llmResponse->stopReason(), $scriptedTokenUsagePlatform->invocations]);
    }

    /**
     * @throws LLMProviderException
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_a_claude_tool_call_cut_off_by_the_output_cap_is_asked_again_with_twice_its_max_tokens(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off'), new TextResult('done')], [new TokenUsage(), new TokenUsage()]);

        (new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'claude-opus-5-5', new NullLogger(), maxOutputTokens: 4096),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        ))->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame([4096, 8192], array_column($scriptedTokenUsagePlatform->invokedOptions, 'max_tokens'));
    }

    /**
     * @throws LLMProviderException
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_a_tool_call_cut_off_without_a_configured_cap_is_not_asked_again(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off'), new TextResult('done')], [new TokenUsage(), new TokenUsage()]);

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'gemini-3.1-pro-preview', new NullLogger()),
            new PlatformRequestConfig(servingPlatform: 'gemini'),
            new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        ))->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame(['length', 1], [$llmResponse->stopReason(), $scriptedTokenUsagePlatform->invocations]);
    }

    /**
     * @throws LLMProviderException
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_a_tool_call_cut_off_by_the_output_cap_is_reported_before_it_is_asked_again(): void
    {
        $messageCollectingLogger = new MessageCollectingLogger();

        $this->client(new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off'), new TextResult('done')], [new TokenUsage(), new TokenUsage()]), $messageCollectingLogger)
            ->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertContains(['LLM tool call cut off by the output token cap, asking again with a higher cap', ['error' => 'cut off']], $messageCollectingLogger->records);
    }

    /**
     * @throws LLMProviderException
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     * @throws InvalidAuditBudgetException
     */
    public function test_a_tool_call_cut_off_by_the_output_cap_is_not_asked_again_once_the_budget_is_spent(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off'), new TextResult('done')], [new TokenUsage(), new TokenUsage()]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'gemini-3.1-pro-preview', new NullLogger(), maxOutputTokens: 4096),
            new PlatformRequestConfig(servingPlatform: 'gemini'),
            new PlatformResilienceConfig(sleeper: new FakeSleeper()),
            new PlatformAccountingConfig(budgetTracker: new BudgetTracker(AuditBudget::forTokens(1), new CostCalculator(new FixedPricingProvider(0.0, 0.0)))),
        );

        try {
            $symfonyAiLLMClient->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);
            self::fail('The raised call went out past the budget.');
        } catch (BudgetExceededException) {
            self::assertSame(1, $scriptedTokenUsagePlatform->invocations);
        }
    }

    private function client(ScriptedTokenUsagePlatform $scriptedTokenUsagePlatform, LoggerInterface $logger = new NullLogger()): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'gemini-3.1-pro-preview', $logger, maxOutputTokens: 4096),
            new PlatformRequestConfig(servingPlatform: 'gemini'),
            new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        );
    }
}
