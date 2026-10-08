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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/**
 * Test fake: a recording tool with a tighter contract than the bundled one,
 * as a custom factory may publish — it refuses a call without a `description`
 * and hands every other call to the tool it wraps.
 */
final readonly class DescriptionRequiringRecordingTool implements RecordingToolInterface
{
    public function __construct(
        private ToolInterface $recordingTool,
    ) {}

    /**
     * @throws InvalidToolDefinitionException
     */
    #[Override]
    public function definition(): ToolDefinition
    {
        return $this->recordingTool->definition();
    }

    #[Override]
    public function execute(array $arguments): string
    {
        if (!\array_key_exists('description', $arguments)) {
            return 'Error: missing required argument "description".';
        }

        return $this->recordingTool->execute($arguments);
    }
}
