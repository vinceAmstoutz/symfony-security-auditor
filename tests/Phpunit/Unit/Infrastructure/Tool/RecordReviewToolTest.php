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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Phpunit\Unit\Infrastructure\Tool;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewTool;

final class RecordReviewToolTest extends TestCase
{
    /**
     * @param array{type: string, maxLength?: int} $expectedConstraints
     */
    #[DataProvider('propertyConstraintCases')]
    public function test_definition_schema_pins_property_constraints(string $propertyName, array $expectedConstraints): void
    {
        $properties = (new RecordReviewTool(new ReviewCollector()))->definition()->parametersSchema['properties'] ?? [];
        self::assertIsArray($properties);
        $property = $properties[$propertyName] ?? null;
        self::assertIsArray($property);

        foreach ($expectedConstraints as $key => $expectedValue) {
            self::assertSame($expectedValue, $property[$key] ?? null, \sprintf('Property "%s" should have %s=%s.', $propertyName, $key, var_export($expectedValue, true)));
        }
    }

    /**
     * @return iterable<string, array{string, array{type: string, maxLength?: int}}>
     */
    public static function propertyConstraintCases(): iterable
    {
        yield 'id is string with 100 char cap' => ['id', ['type' => 'string', 'maxLength' => 100]];
        yield 'accepted is boolean' => ['accepted', ['type' => 'boolean']];
        yield 'adjusted_severity is string' => ['adjusted_severity', ['type' => 'string']];
        yield 'corrected_type is string' => ['corrected_type', ['type' => 'string']];
        yield 'reviewer_notes is string with 5000 char cap' => ['reviewer_notes', ['type' => 'string', 'maxLength' => 5000]];
        yield 'additional_attack_paths is string with 5000 char cap' => ['additional_attack_paths', ['type' => 'string', 'maxLength' => 5000]];
    }

    public function test_definition_exposes_record_review_name(): void
    {
        $recordReviewTool = new RecordReviewTool(new ReviewCollector());

        self::assertSame('record_review', $recordReviewTool->definition()->name);
    }

    public function test_definition_describes_one_call_per_finding(): void
    {
        $recordReviewTool = new RecordReviewTool(new ReviewCollector());

        self::assertStringContainsString('one call per finding', $recordReviewTool->definition()->description);
    }

    public function test_definition_schema_requires_id_and_accepted(): void
    {
        $recordReviewTool = new RecordReviewTool(new ReviewCollector());

        self::assertSame(['id', 'accepted'], $recordReviewTool->definition()->parametersSchema['required'] ?? null);
    }

    public function test_definition_schema_forbids_additional_properties(): void
    {
        $recordReviewTool = new RecordReviewTool(new ReviewCollector());

        self::assertFalse($recordReviewTool->definition()->parametersSchema['additionalProperties'] ?? null);
    }

    public function test_definition_schema_declares_accepted_as_boolean(): void
    {
        $recordReviewTool = new RecordReviewTool(new ReviewCollector());

        $properties = $recordReviewTool->definition()->parametersSchema['properties'] ?? [];
        self::assertIsArray($properties);
        $acceptedProperty = $properties['accepted'] ?? null;
        self::assertIsArray($acceptedProperty);
        self::assertSame('boolean', $acceptedProperty['type'] ?? null);
    }

    public function test_definition_schema_constrains_adjusted_severity_to_enum(): void
    {
        $recordReviewTool = new RecordReviewTool(new ReviewCollector());

        $properties = $recordReviewTool->definition()->parametersSchema['properties'] ?? [];
        self::assertIsArray($properties);
        $severityProperty = $properties['adjusted_severity'] ?? null;
        self::assertIsArray($severityProperty);
        self::assertSame(['critical', 'high', 'medium', 'low', 'info'], $severityProperty['enum'] ?? null);
    }

    public function test_definition_schema_constrains_corrected_type_to_every_vulnerability_type(): void
    {
        $recordReviewTool = new RecordReviewTool(new ReviewCollector());

        $properties = $recordReviewTool->definition()->parametersSchema['properties'] ?? [];
        self::assertIsArray($properties);
        $typeProperty = $properties['corrected_type'] ?? null;
        self::assertIsArray($typeProperty);

        $expected = array_map(
            static fn (VulnerabilityType $vulnerabilityType): string => $vulnerabilityType->value,
            VulnerabilityType::cases(),
        );
        self::assertSame($expected, $typeProperty['enum'] ?? null);
    }

    public function test_definition_schema_declares_id_as_string(): void
    {
        $recordReviewTool = new RecordReviewTool(new ReviewCollector());

        $properties = $recordReviewTool->definition()->parametersSchema['properties'] ?? [];
        self::assertIsArray($properties);
        $idProperty = $properties['id'] ?? null;
        self::assertIsArray($idProperty);
        self::assertSame('string', $idProperty['type'] ?? null);
    }

    public function test_execute_records_the_payload_into_the_collector(): void
    {
        $reviewCollector = new ReviewCollector();
        $recordReviewTool = new RecordReviewTool($reviewCollector);

        $recordReviewTool->execute(['id' => 'VULN-1', 'accepted' => true, 'reviewer_notes' => 'real risk']);

        self::assertSame(
            [['id' => 'VULN-1', 'accepted' => true, 'reviewer_notes' => 'real risk']],
            $reviewCollector->drain(),
        );
    }

    public function test_execute_returns_recorded_acknowledgement(): void
    {
        $recordReviewTool = new RecordReviewTool(new ReviewCollector());

        self::assertSame('recorded', $recordReviewTool->execute(['id' => 'VULN-1', 'accepted' => false]));
    }
}
