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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordingToolClients;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class RecordingToolClientsTest extends TestCase
{
    private const string ATTACKER_WARNING = 'The LLM client never offered the record_vulnerability tool to the model, so its answers are read as JSON; set audit.structured_collection: false for a client that ignores tools.';

    private const string REVIEWER_WARNING = 'The LLM client never offered the record_review tool to the model, so its answers are read as JSON; set audit.reviewer_structured_collection: false for a client that ignores tools.';

    public function test_a_client_that_never_reached_the_tool_ignores_tools_and_is_warned_about_once(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();
        $recordingToolClients = RecordingToolClients::forAttacker($warningCollectingLogger);
        $llmClient = self::createStub(LLMClientInterface::class);
        $recordingToolClients->note($llmClient, false);

        self::assertTrue($recordingToolClients->ignoresTools($llmClient));
        self::assertTrue($recordingToolClients->ignoresTools($llmClient));
        self::assertSame([[self::ATTACKER_WARNING, []]], $warningCollectingLogger->warnings);
    }

    public function test_each_client_that_never_reached_the_tool_is_warned_about_and_the_reviewer_names_its_own_setting(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();
        $recordingToolClients = RecordingToolClients::forReviewer($warningCollectingLogger);

        $recordingToolClients->ignoresTools(self::createStub(LLMClientInterface::class));
        $recordingToolClients->ignoresTools(self::createStub(LLMClientInterface::class));

        self::assertSame([[self::REVIEWER_WARNING, []], [self::REVIEWER_WARNING, []]], $warningCollectingLogger->warnings);
    }

    public function test_a_client_that_reached_the_tool_once_keeps_using_tools_for_the_run_without_a_warning(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();
        $recordingToolClients = RecordingToolClients::forAttacker($warningCollectingLogger);
        $llmClient = self::createStub(LLMClientInterface::class);

        $recordingToolClients->note($llmClient, true);
        $recordingToolClients->note($llmClient, false);

        self::assertFalse($recordingToolClients->ignoresTools($llmClient));
        self::assertSame([], $warningCollectingLogger->warnings);
    }
}
