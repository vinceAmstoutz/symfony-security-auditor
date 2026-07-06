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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;

/**
 * Provider-agnostic description of a tool the LLM may call. The infrastructure
 * adapter is responsible for translating this into the wire format expected by
 * the chosen platform (Anthropic, OpenAI, Mistral, …).
 */
final readonly class ToolDefinition
{
    /**
     * @param array<string, mixed> $parametersSchema JSON Schema describing the tool's input arguments
     *
     * @throws InvalidToolDefinitionException
     */
    public function __construct(
        public string $name,
        public string $description,
        public array $parametersSchema,
    ) {
        if ('' === trim($name)) {
            throw InvalidToolDefinitionException::forBlankName();
        }

        if ('' === trim($description)) {
            throw InvalidToolDefinitionException::forBlankDescription();
        }
    }
}
