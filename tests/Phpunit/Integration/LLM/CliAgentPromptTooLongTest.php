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
use Psr\Log\NullLogger;
use Symfony\AI\Platform\PlatformInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentWorkingDirectory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;

final class CliAgentPromptTooLongTest extends TestCase
{
    private const int LONGEST_COMMAND_LINE_ARGUMENT = 131071;

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_a_prompt_the_command_line_of_a_cli_agent_cannot_carry_is_a_refusal_that_exceeds_the_command_line(): void
    {
        $cliAgentPlatform = new CliAgentPlatform(self::createStub(PlatformInterface::class), new CliAgentWorkingDirectory(), ['sandbox' => 'read-only'], promptsShareOneArgument: true);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($cliAgentPlatform, 'gpt-6.2-sol', new NullLogger()), platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()));

        $caught = null;
        try {
            $symfonyAiLLMClient->complete(str_repeat('s', 72000), str_repeat('u', self::LONGEST_COMMAND_LINE_ARGUMENT - 72000));
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            $caught = $llmRequestTooLargeException;
        }

        self::assertTrue($caught?->exceedsCommandLine());
    }
}
