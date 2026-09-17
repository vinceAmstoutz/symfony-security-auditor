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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfigKeyInstanceName;

final class ConfigKeyInstanceNameTest extends TestCase
{
    #[DataProvider('foldingCases')]
    public function test_it_folds_an_instance_the_way_symfony_config_will(string $instance, string $expected): void
    {
        self::assertSame($expected, ConfigKeyInstanceName::of($instance));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function foldingCases(): iterable
    {
        yield 'a hyphen becomes an underscore' => ['my-gateway', 'my_gateway'];
        yield 'every hyphen becomes an underscore' => ['prod-eu-west', 'prod_eu_west'];
        yield 'an existing underscore stops the fold' => ['my-gate_way', 'my-gate_way'];
        yield 'a name without hyphens is untouched' => ['my_gateway', 'my_gateway'];
        yield 'case is never folded' => ['MY-GATEWAY', 'MY_GATEWAY'];
    }

    #[DataProvider('usabilityCases')]
    public function test_it_rejects_a_name_yaml_cannot_key_a_platform_by(string $instance, bool $expected): void
    {
        self::assertSame($expected, ConfigKeyInstanceName::isUsable($instance));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function usabilityCases(): iterable
    {
        yield 'zero turns the block into a sequence' => ['0', false];
        yield 'another number keys the block by name' => ['42', true];
        yield 'a single digit other than zero keys by name' => ['1', true];
        yield 'leading zeroes keep the name a string' => ['007', true];
        yield 'a negative number is usable' => ['-1', true];
        yield 'a hyphen that folds into a float is refused' => ['1.-', false];
        yield 'digits with a letter name the instance' => ['eu1', true];
        yield 'a leading digit still names the instance' => ['1eu', true];
        yield 'an ordinary name is usable' => ['my_gateway', true];
        yield 'infinity is written unquoted and cannot be read back' => ['.inf', false];
        yield 'not-a-number is written unquoted too' => ['.nan', false];
        yield 'the casing of infinity does not save it' => ['.INF', false];
        yield 'a word that merely looks evaluable is quoted for us' => ['true', true];
        yield 'a yaml tag is resolved away where the writer nests it' => ['!php/const', false];
        yield 'the merge key is not a name the block keeps' => ['<<', false];
    }
}
