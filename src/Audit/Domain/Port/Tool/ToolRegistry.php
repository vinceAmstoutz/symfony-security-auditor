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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool;

use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Holds the catalog of tools available to the attacker agent and dispatches
 * invocation by name. Tool errors are caught and surfaced to the LLM as text
 * results rather than propagating — a misbehaving tool should not kill the audit.
 */
final readonly class ToolRegistry
{
    /** @var array<string, ToolInterface> */
    private array $tools;

    /**
     * @param iterable<ToolInterface> $tools
     */
    public function __construct(
        iterable $tools,
        private LoggerInterface $logger,
    ) {
        $byName = [];
        foreach ($tools as $tool) {
            $name = $tool->definition()->name;
            if (isset($byName[$name])) {
                throw new InvalidArgumentException(\sprintf('Duplicate tool registered: %s', $name));
            }

            $byName[$name] = $tool;
        }

        $this->tools = $byName;
    }

    /**
     * @return list<ToolDefinition>
     */
    public function definitions(): array
    {
        return array_values(array_map(
            static fn (ToolInterface $tool): ToolDefinition => $tool->definition(),
            $this->tools,
        ));
    }

    public function has(string $name): bool
    {
        return isset($this->tools[$name]);
    }

    /**
     * @param array<string, mixed> $arguments
     */
    public function execute(string $name, array $arguments): string
    {
        if (!isset($this->tools[$name])) {
            $this->logger->warning('Tool not found, returning error to LLM', ['tool' => $name]);

            return \sprintf('Error: tool "%s" is not registered. Pick from the provided tool list.', $name);
        }

        try {
            return $this->tools[$name]->execute($arguments);
        } catch (Throwable $throwable) {
            $this->logger->warning('Tool execution failed', [
                'tool' => $name,
                'error' => $throwable->getMessage(),
            ]);

            return \sprintf('Error: tool "%s" failed: %s', $name, $throwable->getMessage());
        }
    }
}
