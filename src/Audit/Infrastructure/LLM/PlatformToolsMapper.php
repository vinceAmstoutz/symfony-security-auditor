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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Tool\ExecutionReference;
use Symfony\AI\Platform\Tool\Tool;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;

/**
 * Maps Domain {@see ToolDefinition}s to symfony/ai platform {@see Tool}s,
 * normalizing each JSON schema to the strict object shape providers validate.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformToolsMapper
{
    /**
     * @param list<ToolDefinition> $definitions
     *
     * @return list<Tool>
     */
    public static function map(array $definitions): array
    {
        return array_map(
            static fn (ToolDefinition $toolDefinition): Tool => new Tool(
                reference: new ExecutionReference(class: ToolCall::class, method: $toolDefinition->name),
                name: $toolDefinition->name,
                description: $toolDefinition->description,
                parameters: self::normalizeSchema($toolDefinition->parametersSchema),
            ),
            $definitions,
        );
    }

    /**
     * @param array<string, mixed> $schema
     *
     * @return array{type: 'object', properties: array<string, array{type: string, description: string}>, required: list<string>, additionalProperties: false}
     */
    private static function normalizeSchema(array $schema): array
    {
        $rawProperties = $schema['properties'] ?? [];
        $properties = [];
        if (\is_array($rawProperties)) {
            foreach ($rawProperties as $name => $spec) {
                if (!\is_string($name)) {
                    continue;
                }

                if (!\is_array($spec)) {
                    continue;
                }

                $type = $spec['type'] ?? 'string';
                $description = $spec['description'] ?? '';
                $properties[$name] = [
                    'type' => \is_string($type) ? $type : 'string',
                    'description' => \is_string($description) ? $description : '',
                ];
            }
        }

        $rawRequired = $schema['required'] ?? [];
        $required = [];
        if (\is_array($rawRequired)) {
            foreach ($rawRequired as $name) {
                if (\is_string($name)) {
                    $required[] = $name;
                }
            }
        }

        return [
            'type' => 'object',
            'properties' => $properties,
            'required' => $required,
            'additionalProperties' => false,
        ];
    }
}
