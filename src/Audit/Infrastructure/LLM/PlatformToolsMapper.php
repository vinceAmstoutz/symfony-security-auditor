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
        return [
            'type' => 'object',
            'properties' => self::normalizeProperties($schema['properties'] ?? []),
            'required' => self::normalizeRequired($schema['required'] ?? []),
            'additionalProperties' => false,
        ];
    }

    /**
     * @return array<string, array{type: string, description: string}>
     */
    private static function normalizeProperties(mixed $rawProperties): array
    {
        if (!\is_array($rawProperties)) {
            return [];
        }

        $properties = [];
        foreach ($rawProperties as $name => $spec) {
            if (!\is_string($name)) {
                continue;
            }

            if (!\is_array($spec)) {
                continue;
            }

            $properties[$name] = self::normalizePropertySpec($spec);
        }

        return $properties;
    }

    /**
     * @param array<array-key, mixed> $spec
     *
     * @return array{type: string, description: string}
     */
    private static function normalizePropertySpec(array $spec): array
    {
        $type = $spec['type'] ?? 'string';
        $description = $spec['description'] ?? '';

        return [
            'type' => \is_string($type) ? $type : 'string',
            'description' => \is_string($description) ? $description : '',
        ];
    }

    /**
     * @return list<string>
     */
    private static function normalizeRequired(mixed $rawRequired): array
    {
        if (!\is_array($rawRequired)) {
            return [];
        }

        $required = [];
        foreach ($rawRequired as $name) {
            if (\is_string($name)) {
                $required[] = $name;
            }
        }

        return $required;
    }
}
