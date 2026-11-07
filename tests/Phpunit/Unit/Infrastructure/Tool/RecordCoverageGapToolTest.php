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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Tool;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageGapCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordCoverageGapTool;

final class RecordCoverageGapToolTest extends TestCase
{
    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_the_tool_is_named_record_coverage_gap(): void
    {
        self::assertSame('record_coverage_gap', (new RecordCoverageGapTool(new CoverageGapCollector()))->definition()->name);
    }

    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_a_gap_requires_its_files_hypothesis_and_attack_class_and_nothing_else(): void
    {
        $schema = (new RecordCoverageGapTool(new CoverageGapCollector()))->definition()->parametersSchema;

        self::assertSame(
            [['files', 'hypothesis', 'attack_class'], false],
            [$schema['required'] ?? null, $schema['additionalProperties'] ?? null],
        );
    }

    /**
     * @param array<string, mixed> $expectedConstraints
     *
     * @throws InvalidToolDefinitionException
     */
    #[DataProvider('propertyConstraints')]
    public function test_each_field_of_a_gap_is_bounded(string $property, array $expectedConstraints): void
    {
        $properties = (new RecordCoverageGapTool(new CoverageGapCollector()))->definition()->parametersSchema['properties'] ?? [];
        self::assertIsArray($properties);
        $schema = $properties[$property] ?? null;
        self::assertIsArray($schema);

        self::assertSame($expectedConstraints, array_intersect_key($schema, $expectedConstraints));
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function propertyConstraints(): iterable
    {
        yield 'files lists one to ten paths of at most 500 characters' => ['files', ['type' => 'array', 'items' => ['type' => 'string', 'maxLength' => 500], 'minItems' => 1, 'maxItems' => 10]];
        yield 'hypothesis is text of at most 2000 characters' => ['hypothesis', ['type' => 'string', 'maxLength' => 2000]];
        yield 'attack_class is text of at most 100 characters' => ['attack_class', ['type' => 'string', 'maxLength' => 100]];
    }

    public function test_a_complete_call_is_recorded_into_the_collector(): void
    {
        $coverageGapCollector = new CoverageGapCollector();
        $arguments = ['files' => ['src/Controller/ExportController.php'], 'hypothesis' => 'The export skips the owner check.', 'attack_class' => 'broken_access_control'];

        $answer = (new RecordCoverageGapTool($coverageGapCollector))->execute($arguments);

        self::assertSame(['recorded', [$arguments]], [$answer, $coverageGapCollector->drain()]);
    }

    #[DataProvider('requiredArguments')]
    public function test_a_call_missing_a_required_argument_is_refused_and_records_nothing(string $name): void
    {
        $coverageGapCollector = new CoverageGapCollector();
        $arguments = ['files' => ['src/Controller/ExportController.php'], 'hypothesis' => 'The export skips the owner check.', 'attack_class' => 'broken_access_control'];
        unset($arguments[$name]);

        $answer = (new RecordCoverageGapTool($coverageGapCollector))->execute($arguments);

        self::assertSame([\sprintf('Error: missing required argument "%s".', $name), []], [$answer, $coverageGapCollector->drain()]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function requiredArguments(): iterable
    {
        yield 'files' => ['files'];
        yield 'hypothesis' => ['hypothesis'];
        yield 'attack_class' => ['attack_class'];
    }
}
