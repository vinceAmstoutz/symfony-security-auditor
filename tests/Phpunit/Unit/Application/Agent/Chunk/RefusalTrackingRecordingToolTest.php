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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\RefusalTrackingRecordingTool;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\RecordingToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\AnsweringRecordingTool;

final class RefusalTrackingRecordingToolTest extends TestCase
{
    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_it_publishes_the_definition_of_the_tool_it_wraps(): void
    {
        $answeringRecordingTool = new AnsweringRecordingTool(RecordingToolInterface::RECORDED);

        $refusalTrackingRecordingTool = new RefusalTrackingRecordingTool($answeringRecordingTool, new VulnerabilityCollector());

        self::assertEquals($answeringRecordingTool->definition(), $refusalTrackingRecordingTool->definition());
    }

    public function test_a_call_the_wrapped_tool_recorded_is_answered_as_it_was_and_reports_no_refusal(): void
    {
        $vulnerabilityCollector = new VulnerabilityCollector();
        $refusalTrackingRecordingTool = new RefusalTrackingRecordingTool(new AnsweringRecordingTool(RecordingToolInterface::RECORDED), $vulnerabilityCollector);

        $answer = $refusalTrackingRecordingTool->execute(['file_path' => 'src/A.php', 'title' => 'SQLi']);

        self::assertSame('recorded', $answer);
        self::assertSame(0, $vulnerabilityCollector->unsettledRefusals());
    }

    public function test_a_call_the_wrapped_tool_refused_is_answered_as_it_was_and_reported_with_its_arguments(): void
    {
        $vulnerabilityCollector = new VulnerabilityCollector();
        $refusalTrackingRecordingTool = new RefusalTrackingRecordingTool(new AnsweringRecordingTool('Error: missing required argument "description".'), $vulnerabilityCollector);

        $answer = $refusalTrackingRecordingTool->execute(['file_path' => 'src/A.php', 'title' => 'SQLi']);

        self::assertSame('Error: missing required argument "description".', $answer);
        self::assertSame(1, $vulnerabilityCollector->unsettledRefusals());
        $vulnerabilityCollector->add(['file_path' => 'src/A.php', 'title' => 'SQLi']);
        self::assertSame(0, $vulnerabilityCollector->unsettledRefusals());
    }
}
