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
 * Test fake: a reading tool that counts the calls it actually ran, so a test
 * can tell a call that was executed from one that was only answered.
 */
final readonly class CountingReadingTool implements ToolInterface
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
        return new ToolDefinition($this->name, 'reads a file', ['type' => 'object', 'properties' => [], 'required' => []]);
    }

    #[Override]
    public function execute(array $arguments): string
    {
        ++$this->toolCallCounter->calls;

        return 'a file';
    }
}
