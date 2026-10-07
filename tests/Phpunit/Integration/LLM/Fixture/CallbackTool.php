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

use Closure;
use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

final readonly class CallbackTool implements ToolInterface
{
    /**
     * @param ?Closure(array<string, mixed>): string $executor
     * @param array<string, mixed>                   $parametersSchema
     */
    public function __construct(
        private string $name,
        private string $description,
        private ?Closure $executor = null,
        private array $parametersSchema = ['type' => 'object', 'properties' => [], 'required' => []],
    ) {}

    /**
     * @throws InvalidToolDefinitionException
     */
    #[Override]
    public function definition(): ToolDefinition
    {
        return new ToolDefinition($this->name, $this->description, $this->parametersSchema);
    }

    #[Override]
    public function execute(array $arguments): string
    {
        return $this->executor instanceof Closure ? ($this->executor)($arguments) : 'ok';
    }
}
