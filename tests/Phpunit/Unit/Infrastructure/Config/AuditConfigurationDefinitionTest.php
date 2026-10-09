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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;

final class AuditConfigurationDefinitionTest extends TestCase
{
    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('nullableNumericKeys')]
    public function test_an_explicit_null_on_a_nullable_numeric_key_is_accepted_as_null(array $path): void
    {
        $processed = $this->process([self::nested($path, null)]);

        self::assertNull($this->valueAt($processed, $path));
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('nullableNumericKeysWithANumber')]
    public function test_an_explicit_null_resets_a_value_set_by_an_earlier_configuration(array $path, int|float $number): void
    {
        $processed = $this->process([self::nested($path, $number), self::nested($path, null)]);

        self::assertNull($this->valueAt($processed, $path));
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('nullableNumericKeysWithANumber')]
    public function test_a_nullable_numeric_key_still_reads_a_number(array $path, int|float $number): void
    {
        $processed = $this->process([self::nested($path, $number)]);

        self::assertSame($number, $this->valueAt($processed, $path));
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('nullableNumericKeysWithAValueBelowTheirMinimum')]
    public function test_a_nullable_numeric_key_still_refuses_a_value_below_its_minimum(array $path, int|float $belowMinimum): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process([self::nested($path, $belowMinimum)]);
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('nullableNumericKeys')]
    public function test_a_nullable_numeric_key_still_refuses_a_value_that_is_no_number(array $path): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process([self::nested($path, 'many')]);
    }

    public function test_min_score_accepts_one_hundred(): void
    {
        $processed = $this->process([['audit' => ['min_score' => 100]]]);

        self::assertSame(100, $this->valueAt($processed, ['audit', 'min_score']));
    }

    public function test_min_score_refuses_a_value_above_one_hundred(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process([['audit' => ['min_score' => 101]]]);
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('modelOverrideKeys')]
    public function test_a_blank_model_override_is_refused_naming_the_key(array $path): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(\sprintf('The path "symfony_security_auditor.%s" cannot contain an empty value, but got "".', implode('.', $path)));

        $this->process([self::nested($path, '')]);
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('modelOverrideKeys')]
    public function test_an_explicit_null_model_override_is_accepted_as_null(array $path): void
    {
        $processed = $this->process([self::nested($path, null)]);

        self::assertNull($this->valueAt($processed, $path));
    }

    /**
     * @param non-empty-list<string> $path
     */
    #[DataProvider('modelOverrideKeys')]
    public function test_a_model_override_that_is_not_text_is_refused_naming_the_key(array $path): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(\sprintf('Invalid type for path "symfony_security_auditor.%s". Expected "string", but got "int".', implode('.', $path)));

        $this->process([self::nested($path, 4)]);
    }

    /**
     * @return iterable<string, array{non-empty-list<string>}>
     */
    public static function modelOverrideKeys(): iterable
    {
        yield 'attacker_model' => [['attacker_model']];
        yield 'reviewer_model' => [['reviewer_model']];
        yield 'audit.escalation.cheap_model' => [['audit', 'escalation', 'cheap_model']];
    }

    /**
     * @return iterable<string, array{non-empty-list<string>}>
     */
    public static function nullableNumericKeys(): iterable
    {
        foreach (self::keysWithTheirNumbers() as $name => [$path]) {
            yield $name => [$path];
        }
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, int|float}>
     */
    public static function nullableNumericKeysWithANumber(): iterable
    {
        foreach (self::keysWithTheirNumbers() as $name => [$path, $number]) {
            yield $name => [$path, $number];
        }
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, int|float}>
     */
    public static function nullableNumericKeysWithAValueBelowTheirMinimum(): iterable
    {
        foreach (self::keysWithTheirNumbers() as $name => [$path, , $belowMinimum]) {
            yield $name => [$path, $belowMinimum];
        }
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, int|float, int|float}>
     */
    private static function keysWithTheirNumbers(): iterable
    {
        yield 'attacker_max_output_tokens' => [['attacker_max_output_tokens'], 8, 0];
        yield 'reviewer_max_output_tokens' => [['reviewer_max_output_tokens'], 8, 0];
        yield 'audit.max_iterations' => [['audit', 'max_iterations'], 8, 0];
        yield 'audit.attacker_max_concurrent' => [['audit', 'attacker_max_concurrent'], 8, 0];
        yield 'audit.reviewer_max_concurrent' => [['audit', 'reviewer_max_concurrent'], 8, 0];
        yield 'audit.min_score' => [['audit', 'min_score'], 80, -1];
        yield 'audit.budget.max_tokens' => [['audit', 'budget', 'max_tokens'], 8, 0];
        yield 'audit.budget.max_cost_usd' => [['audit', 'budget', 'max_cost_usd'], 8.5, 0.0];
        yield 'audit.rate_limit.requests_per_minute' => [['audit', 'rate_limit', 'requests_per_minute'], 8, 0];
        yield 'audit.rate_limit.input_tokens_per_minute' => [['audit', 'rate_limit', 'input_tokens_per_minute'], 8, 0];
        yield 'audit.rate_limit.output_tokens_per_minute' => [['audit', 'rate_limit', 'output_tokens_per_minute'], 8, 0];
    }

    /**
     * @param list<array<array-key, mixed>> $configs
     *
     * @return array<array-key, mixed>
     */
    private function process(array $configs): array
    {
        $treeBuilder = new TreeBuilder('symfony_security_auditor');
        (new AuditConfigurationDefinition())->defineChildren($treeBuilder->getRootNode()->children());

        return (new Processor())->process($treeBuilder->buildTree(), $configs);
    }

    /**
     * @param non-empty-list<string> $path
     *
     * @return array<array-key, mixed>
     */
    private static function nested(array $path, mixed $value): array
    {
        $key = array_shift($path);

        return [$key => [] === $path ? $value : self::nested($path, $value)];
    }

    /**
     * @param array<array-key, mixed> $config
     * @param list<string>            $path
     */
    private function valueAt(array $config, array $path): mixed
    {
        $value = $config;

        foreach ($path as $key) {
            self::assertIsArray($value);
            $value = $value[$key];
        }

        return $value;
    }
}
