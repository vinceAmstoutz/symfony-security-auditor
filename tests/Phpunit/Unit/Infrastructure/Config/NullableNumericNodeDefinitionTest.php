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
use Symfony\Component\Config\Definition\Builder\NumericNodeDefinition;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\NullableFloatNodeDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\NullableIntegerNodeDefinition;

final class NullableNumericNodeDefinitionTest extends TestCase
{
    #[DataProvider('numericDefinitionsBetweenTwoAndFive')]
    public function test_it_accepts_null(NumericNodeDefinition $numericNodeDefinition): void
    {
        self::assertNull($numericNodeDefinition->getNode()->finalize(null));
    }

    #[DataProvider('numericDefinitionsBetweenTwoAndFive')]
    public function test_it_accepts_both_ends_of_its_range(NumericNodeDefinition $numericNodeDefinition): void
    {
        $node = $numericNodeDefinition->getNode();

        self::assertSame(2, $node->finalize(2));
        self::assertSame(5, $node->finalize(5));
    }

    #[DataProvider('numericDefinitionsBetweenTwoAndFive')]
    public function test_it_refuses_a_value_below_its_minimum(NumericNodeDefinition $numericNodeDefinition): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $numericNodeDefinition->getNode()->finalize(1);
    }

    #[DataProvider('numericDefinitionsBetweenTwoAndFive')]
    public function test_it_refuses_a_value_above_its_maximum(NumericNodeDefinition $numericNodeDefinition): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $numericNodeDefinition->getNode()->finalize(6);
    }

    #[DataProvider('numericDefinitionsBetweenTwoAndFive')]
    public function test_it_refuses_a_string(NumericNodeDefinition $numericNodeDefinition): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $numericNodeDefinition->getNode()->finalize('3');
    }

    /**
     * @return iterable<string, array{NumericNodeDefinition}>
     */
    public static function numericDefinitionsBetweenTwoAndFive(): iterable
    {
        yield 'integer' => [(new NullableIntegerNodeDefinition('limit'))->min(2)->max(5)];
        yield 'float' => [(new NullableFloatNodeDefinition('limit'))->min(2)->max(5)];
    }
}
