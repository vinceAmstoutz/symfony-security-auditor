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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\RecordingToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;

/**
 * Test fake: a recording tool that counts how many times it was called.
 */
final readonly class CountingRecordingTool implements RecordingToolInterface
{
    public function __construct(
        private string $name,
        private ToolCallCounter $toolCallCounter,
    ) {}

    /**
     * @throws InvalidToolDefinitionException
     */
    #[Override]
    public function definition(): ToolDefinition
    {
        return new ToolDefinition($this->name, 'records an answer', ['type' => 'object', 'properties' => [], 'required' => []]);
    }

    #[Override]
    public function execute(array $arguments): string
    {
        ++$this->toolCallCounter->calls;

        return 'recorded';
    }
}
