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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RequiredArguments;

final class RequiredArgumentsTest extends TestCase
{
    private const array SCHEMA = [
        'type' => 'object',
        'properties' => [
            'name' => ['type' => 'string'],
            'count' => ['type' => 'integer'],
            'ratio' => ['type' => 'number'],
            'flag' => ['type' => 'boolean'],
            'note' => ['type' => 'string'],
        ],
        'required' => ['name', 'count', 'ratio', 'flag'],
    ];

    public function test_complete_arguments_have_no_violation(): void
    {
        self::assertNull(RequiredArguments::violation(self::SCHEMA, ['name' => 'a', 'count' => 3, 'ratio' => 0.5, 'flag' => true]));
    }

    public function test_an_argument_the_schema_does_not_require_may_be_absent_or_null(): void
    {
        self::assertNull(RequiredArguments::violation(self::SCHEMA, ['name' => 'a', 'count' => 3, 'ratio' => 0.5, 'flag' => true, 'note' => null]));
    }

    #[DataProvider('falsyButPresentValues')]
    public function test_a_present_value_is_never_taken_for_a_missing_one(string $name, mixed $value): void
    {
        $arguments = ['name' => 'a', 'count' => 3, 'ratio' => 0.5, 'flag' => true, $name => $value];

        self::assertNull(RequiredArguments::violation(self::SCHEMA, $arguments));
    }

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function falsyButPresentValues(): iterable
    {
        yield 'false for a boolean' => ['flag', false];
        yield 'zero for an integer' => ['count', 0];
        yield 'zero for a number' => ['ratio', 0.0];
        yield 'an empty string for a string' => ['name', ''];
    }

    #[DataProvider('requiredNames')]
    public function test_an_absent_required_argument_is_reported_by_name(string $name): void
    {
        $arguments = ['name' => 'a', 'count' => 3, 'ratio' => 0.5, 'flag' => true];
        unset($arguments[$name]);

        self::assertSame(\sprintf('Error: missing required argument "%s".', $name), RequiredArguments::violation(self::SCHEMA, $arguments));
    }

    #[DataProvider('requiredNames')]
    public function test_a_null_required_argument_is_reported_as_missing(string $name): void
    {
        $arguments = ['name' => 'a', 'count' => 3, 'ratio' => 0.5, 'flag' => true, $name => null];

        self::assertSame(\sprintf('Error: missing required argument "%s".', $name), RequiredArguments::violation(self::SCHEMA, $arguments));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function requiredNames(): iterable
    {
        foreach (self::SCHEMA['required'] as $name) {
            yield $name => [$name];
        }
    }

    #[DataProvider('nonStringValues')]
    public function test_a_string_argument_must_hold_a_string(mixed $value): void
    {
        self::assertSame(
            'Error: argument "name" must be a string.',
            RequiredArguments::violation(self::SCHEMA, ['name' => $value, 'count' => 3, 'ratio' => 0.5, 'flag' => true]),
        );
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function nonStringValues(): iterable
    {
        yield 'an integer' => [5];
        yield 'a boolean' => [true];
        yield 'a list' => [['VULN-1']];
    }

    #[DataProvider('stringifiedValues')]
    public function test_a_stringified_number_or_boolean_is_left_to_the_downstream_normalisation(string $name, string $value): void
    {
        $arguments = ['name' => 'a', 'count' => 3, 'ratio' => 0.5, 'flag' => true, $name => $value];

        self::assertNull(RequiredArguments::violation(self::SCHEMA, $arguments));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function stringifiedValues(): iterable
    {
        yield 'an integer as text' => ['count', '12'];
        yield 'a number as text' => ['ratio', '0.9'];
        yield 'a boolean as text' => ['flag', 'true'];
    }

    public function test_the_first_violation_in_schema_order_is_the_one_reported(): void
    {
        self::assertSame(
            'Error: missing required argument "count".',
            RequiredArguments::violation(self::SCHEMA, ['name' => 'a']),
        );
    }

    public function test_a_required_argument_the_schema_declares_no_property_for_is_only_checked_for_presence(): void
    {
        $schema = ['required' => ['extra'], 'properties' => []];

        self::assertNull(RequiredArguments::violation($schema, ['extra' => 5]));
        self::assertSame('Error: missing required argument "extra".', RequiredArguments::violation($schema, []));
    }
}
