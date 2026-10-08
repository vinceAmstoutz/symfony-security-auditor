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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\RecordingToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;

/**
 * Test fake: a recording tool that answers every call with the same text and
 * records nothing, so a test decides whether the call counts as recorded.
 */
final readonly class AnsweringRecordingTool implements RecordingToolInterface
{
    public function __construct(
        private string $answer,
    ) {}

    /**
     * @throws InvalidToolDefinitionException
     */
    #[Override]
    public function definition(): ToolDefinition
    {
        return new ToolDefinition('record_vulnerability', 'answers with a fixed text', ['type' => 'object', 'properties' => [], 'required' => []]);
    }

    #[Override]
    public function execute(array $arguments): string
    {
        return $this->answer;
    }
}
