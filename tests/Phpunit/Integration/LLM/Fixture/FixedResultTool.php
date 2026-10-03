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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/**
 * Test fake: a tool that answers every call with the same text, so a test can
 * decide how much a tool round adds to the conversation.
 */
final readonly class FixedResultTool implements ToolInterface
{
    public function __construct(
        private string $name,
        private string $result,
    ) {}

    /**
     * @throws InvalidToolDefinitionException
     */
    #[Override]
    public function definition(): ToolDefinition
    {
        return new ToolDefinition($this->name, 'answers with a fixed text', ['type' => 'object', 'properties' => [], 'required' => []]);
    }

    #[Override]
    public function execute(array $arguments): string
    {
        return $this->result;
    }
}
