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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Tool\Tool;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformToolsMapper;

final class PlatformToolsMapperTest extends TestCase
{
    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_it_maps_the_basic_object_shape(): void
    {
        $toolDefinition = new ToolDefinition(
            name: 'record_vulnerability',
            description: 'records a finding',
            parametersSchema: [
                'type' => 'object',
                'properties' => ['title' => ['type' => 'string', 'description' => 'the title']],
                'required' => ['title'],
            ],
        );

        $tool = PlatformToolsMapper::map([$toolDefinition])[0];

        self::assertSame('record_vulnerability', $tool->getName());
        self::assertSame([
            'type' => 'object',
            'properties' => ['title' => ['type' => 'string', 'description' => 'the title']],
            'required' => ['title'],
            'additionalProperties' => false,
        ], $this->parametersOf($tool));
    }

    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_it_preserves_the_enum_constraint(): void
    {
        $toolDefinition = new ToolDefinition(
            name: 'record_vulnerability',
            description: 'records a finding',
            parametersSchema: [
                'type' => 'object',
                'properties' => ['severity' => ['type' => 'string', 'description' => 'x', 'enum' => ['low', 'high']]],
                'required' => [],
            ],
        );

        $tool = PlatformToolsMapper::map([$toolDefinition])[0];

        self::assertSame(['low', 'high'], $this->parametersOf($tool)['properties']['severity']['enum']);
    }

    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_it_preserves_the_minimum_and_maximum_constraints(): void
    {
        $toolDefinition = new ToolDefinition(
            name: 'record_vulnerability',
            description: 'records a finding',
            parametersSchema: [
                'type' => 'object',
                'properties' => ['confidence' => ['type' => 'number', 'description' => 'x', 'minimum' => 0.0, 'maximum' => 1.0]],
                'required' => [],
            ],
        );

        $tool = PlatformToolsMapper::map([$toolDefinition])[0];
        $parameters = $this->parametersOf($tool);

        self::assertSame(0.0, $parameters['properties']['confidence']['minimum']);
        self::assertSame(1.0, $parameters['properties']['confidence']['maximum']);
    }

    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_it_preserves_the_max_length_constraint(): void
    {
        $toolDefinition = new ToolDefinition(
            name: 'record_vulnerability',
            description: 'records a finding',
            parametersSchema: [
                'type' => 'object',
                'properties' => ['title' => ['type' => 'string', 'description' => 'x', 'maxLength' => 500]],
                'required' => [],
            ],
        );

        $tool = PlatformToolsMapper::map([$toolDefinition])[0];

        self::assertSame(500, $this->parametersOf($tool)['properties']['title']['maxLength']);
    }

    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_it_omits_unrecognized_constraint_keywords(): void
    {
        $toolDefinition = new ToolDefinition(
            name: 'record_vulnerability',
            description: 'records a finding',
            parametersSchema: [
                'type' => 'object',
                'properties' => ['title' => ['type' => 'string', 'description' => 'x', 'pattern' => '^[a-z]+$']],
                'required' => [],
            ],
        );

        $tool = PlatformToolsMapper::map([$toolDefinition])[0];

        self::assertArrayNotHasKey('pattern', $this->parametersOf($tool)['properties']['title']);
    }

    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_it_preserves_the_items_schema_of_an_array_property(): void
    {
        $toolDefinition = new ToolDefinition(
            name: 'record_vulnerability',
            description: 'records a finding',
            parametersSchema: [
                'type' => 'object',
                'properties' => ['tags' => ['type' => 'array', 'description' => 'x', 'items' => ['type' => 'string', 'description' => 'a tag']]],
                'required' => [],
            ],
        );

        $tool = PlatformToolsMapper::map([$toolDefinition])[0];

        self::assertSame(['type' => 'string', 'description' => 'a tag'], $this->parametersOf($tool)['properties']['tags']['items']);
    }

    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_it_preserves_the_nested_properties_of_an_object_property(): void
    {
        $toolDefinition = new ToolDefinition(
            name: 'record_vulnerability',
            description: 'records a finding',
            parametersSchema: [
                'type' => 'object',
                'properties' => ['location' => [
                    'type' => 'object',
                    'description' => 'x',
                    'properties' => ['file' => ['type' => 'string', 'description' => 'the file']],
                    'required' => ['file'],
                ]],
                'required' => [],
            ],
        );

        $tool = PlatformToolsMapper::map([$toolDefinition])[0];
        $location = $this->parametersOf($tool)['properties']['location'];

        self::assertSame(['file' => ['type' => 'string', 'description' => 'the file']], $location['properties']);
        self::assertSame(['file'], $location['required']);
        self::assertFalse($location['additionalProperties']);
    }

    /**
     * @return array{type: 'object', properties: array<string, array<string, mixed>>, required: list<string>, additionalProperties: false}
     */
    private function parametersOf(Tool $tool): array
    {
        $parameters = $tool->getParameters();
        self::assertNotNull($parameters);

        return $parameters;
    }
}
