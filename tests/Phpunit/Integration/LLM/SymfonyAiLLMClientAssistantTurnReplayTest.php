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
use Symfony\AI\Platform\Message\AssistantMessage;
use Symfony\AI\Platform\Message\Content\Text;
use Symfony\AI\Platform\Message\Content\Thinking;
use Symfony\AI\Platform\Message\MessageInterface;
use Symfony\AI\Platform\Message\ToolCallMessage;
use Symfony\AI\Platform\Result\MultiPartResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ThinkingResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedResultTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedResultPlatform;

/**
 * A tool-using conversation sends the model's own answer back with the tool
 * results. A model that reasons before it calls a tool answers with a signed
 * thinking block, the tool calls and sometimes text in between, and Anthropic
 * refuses the next request unless that very turn comes back unmodified.
 */
final class SymfonyAiLLMClientAssistantTurnReplayTest extends TestCase
{
    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws LLMRequestTooLargeException
     */
    public function test_complete_with_tools_replays_the_whole_assistant_turn_with_its_signed_thinking_block(): void
    {
        $scriptedResultPlatform = $this->platformAnsweringWithAThinkingTurnThenText();

        $this->client($scriptedResultPlatform)->completeWithTools('sys', 'user', $this->registry(), 4);

        $this->assertTheTurnWasReplayedWhole($scriptedResultPlatform);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_replays_the_whole_assistant_turn_with_its_signed_thinking_block(): void
    {
        $scriptedResultPlatform = $this->platformAnsweringWithAThinkingTurnThenText();

        $this->client($scriptedResultPlatform)->completeBatchWithTools([['system' => 'sys', 'user' => 'user', 'tools' => $this->registry()]], 1, 4);

        $this->assertTheTurnWasReplayedWhole($scriptedResultPlatform);
    }

    private function assertTheTurnWasReplayedWhole(ScriptedResultPlatform $scriptedResultPlatform): void
    {
        self::assertCount(2, $scriptedResultPlatform->requests);
        $assistantTurns = array_values(array_filter($scriptedResultPlatform->requests[1], static fn (MessageInterface $message): bool => $message instanceof AssistantMessage));
        self::assertCount(1, $assistantTurns);

        [$thinking, $text, $firstCall, $secondCall] = $assistantTurns[0]->getContent();
        self::assertInstanceOf(Thinking::class, $thinking);
        self::assertSame('I should look the file up first', $thinking->getContent());
        self::assertSame('signature-from-the-provider', $thinking->getSignature());
        self::assertInstanceOf(Text::class, $text);
        self::assertSame('Let me look that up.', $text->getText());
        self::assertInstanceOf(ToolCall::class, $firstCall);
        self::assertSame('call-1', $firstCall->getId());
        self::assertInstanceOf(ToolCall::class, $secondCall);
        self::assertSame('call-2', $secondCall->getId());
        self::assertCount(4, $assistantTurns[0]->getContent());

        $toolResults = array_values(array_filter($scriptedResultPlatform->requests[1], static fn (MessageInterface $message): bool => $message instanceof ToolCallMessage));
        self::assertCount(2, $toolResults);
    }

    private function platformAnsweringWithAThinkingTurnThenText(): ScriptedResultPlatform
    {
        return new ScriptedResultPlatform([
            new MultiPartResult([
                new ThinkingResult('I should look the file up first', 'signature-from-the-provider'),
                new TextResult('Let me look that up.'),
                new ToolCallResult([new ToolCall('call-1', 'lookup'), new ToolCall('call-2', 'lookup')]),
            ]),
            new TextResult('done'),
        ]);
    }

    /**
     * @throws InvalidToolRegistryException
     */
    private function registry(): ToolRegistry
    {
        return new ToolRegistry([new FixedResultTool('lookup', 'a file')], new NullLogger());
    }

    private function client(ScriptedResultPlatform $scriptedResultPlatform): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(new PlatformBinding($scriptedResultPlatform, 'm', new NullLogger()));
    }
}
