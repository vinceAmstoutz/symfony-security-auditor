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
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ContainerParameterSyntax;

final class ContainerParameterSyntaxTest extends TestCase
{
    #[DataProvider('valueCases')]
    public function test_it_reports_whether_a_value_is_free_of_parameter_references(string $value, bool $expected): void
    {
        self::assertSame($expected, ContainerParameterSyntax::isAbsentFrom($value));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function valueCases(): iterable
    {
        yield 'an ordinary origin is accepted' => ['https://gw.example', true];
        yield 'a lone percent is not a reference' => ['https://gw.example/100%done', true];
        yield 'an env placeholder is resolved before the container sees it' => ['%env(GATEWAY_URL)%', true];
        yield 'a file env placeholder is resolved too' => ['%env(file:GATEWAY_URL)%', true];
        yield 'a parameter reference inside a url is refused' => ['https://gw.example/%v%', false];
        yield 'a bare parameter reference is refused' => ['%v%', false];
        yield 'an escaped percent would be rewritten, so it is refused' => ['https://gw.example/a%%b', false];
        yield 'a percent pair spanning whitespace is not a reference' => ['https://gw.example/?d=50% off 20%', true];
        yield 'an env placeholder with a suffix is not the whole value' => ['%env(GATEWAY_URL)%/v1', false];
    }

    #[DataProvider('referenceCases')]
    public function test_it_tells_whether_the_container_would_read_a_reference_in_a_value(string $value, bool $expected): void
    {
        self::assertSame($expected, ContainerParameterSyntax::holdsReference($value));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function referenceCases(): iterable
    {
        yield 'an env placeholder reads the environment' => ['%env(AWS_SECRET_ACCESS_KEY)%', true];
        yield 'a parameter reference inside a value' => ['claude-%kernel.project_dir%', true];
        yield 'an escaped percent is rewritten' => ['a%%b', true];
        yield 'a lone percent is text' => ['baseline-100%.json', false];
        yield 'a percent pair spanning whitespace is text' => ['50% off 20%', false];
        yield 'no percent at all' => ['claude-opus-4-8', false];
    }

    #[DataProvider('envPlaceholderCases')]
    public function test_it_tells_whether_a_value_spells_the_placeholder_the_container_substitutes_for_an_env_var(string $value, bool $expected): void
    {
        self::assertSame($expected, ContainerParameterSyntax::holdsEnvPlaceholder($value));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function envPlaceholderCases(): iterable
    {
        yield 'the placeholder of an env var the user config reads' => ['env_34f75a56af7a1fe6_PROBE_SECRET_84e03e7752b3d04c14ede66becacf7ea', true];
        yield 'the same placeholder in capitals' => ['claude-ENV_34F75A56AF7A1FE6_PROBE_SECRET', true];
        yield 'a prefix one hex digit short' => ['env_34f75a56af7a1fe_PROBE', false];
        yield 'a prefix holding a letter past f' => ['env_34f75a56af7a1feg_PROBE', false];
        yield 'an ordinary model name' => ['claude-opus-4-8', false];
    }

    #[DataProvider('urlCases')]
    public function test_it_tells_a_percent_encoded_url_from_one_holding_a_parameter_reference(string $url, bool $expected): void
    {
        self::assertSame($expected, ContainerParameterSyntax::isAbsentFromUrl($url));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function urlCases(): iterable
    {
        yield 'an ordinary origin' => ['https://gw.example', true];
        yield 'one percent-encoded octet' => ['https://gw.example/v1%2Fx', true];
        yield 'several percent-encoded octets' => ['https://gw.example/v1%2Fx%3Fy', true];
        yield 'lowercase hex digits' => ['https://gw.example/a%2fb%3fc', true];
        yield 'a whole-value env placeholder is left to the caller' => ['%env(GATEWAY_URL)%', false];
        yield 'a lone percent that starts no octet' => ['https://gw.example/100%', false];
        yield 'a parameter reference' => ['https://gw.example/%v%', false];
        yield 'an env placeholder inside the url' => ['https://%env(GATEWAY_HOST)%/v1', false];
        yield 'an escaped percent' => ['https://gw.example/a%%b', false];
        yield 'a parameter reference beside an encoded octet' => ['https://gw.example/%2F%v%', false];
        yield 'a whole-value reference whose name opens with two hex digits' => ['%BASE_URL%', false];
        yield 'a reference inside the url whose name is hex' => ['https://gw.example/%dead%/v1', false];
        yield 'a reference whose name opens with hex, beside an encoded octet' => ['https://gw.example/%2F%cafe_host%', false];
    }

    #[DataProvider('literalCases')]
    public function test_it_spells_a_value_so_the_container_reads_it_back_as_written(string $value, string $expected): void
    {
        self::assertSame($expected, ContainerParameterSyntax::literal($value));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function literalCases(): iterable
    {
        yield 'a value without a percent' => ['https://gw.example', 'https://gw.example'];
        yield 'every percent is doubled' => ['https://gw.example/v1%2Fx%3Fy', 'https://gw.example/v1%%2Fx%%3Fy'];
        yield 'a whole-value env placeholder is left for the resolver' => ['%env(GATEWAY_URL)%', '%env(GATEWAY_URL)%'];
    }

    #[DataProvider('unresolvableCases')]
    public function test_it_escapes_the_percent_pairs_the_container_could_not_resolve(string $value, string $expected): void
    {
        self::assertSame($expected, ContainerParameterSyntax::escapeUnresolvable($value, new ParameterBag(['kernel.project_dir' => '/srv/app'])));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function unresolvableCases(): iterable
    {
        yield 'two pairs naming no parameter' => ['/sprintf\(.*%s.*%d/', '/sprintf\(.*%%s.*%%d/'];
        yield 'a range of percentages' => ['a discount between 50%-60% is fine', 'a discount between 50%%-60%% is fine'];
        yield 'a reference to a parameter that exists' => ['%kernel.project_dir%/src', '%kernel.project_dir%/src'];
        yield 'an environment placeholder' => ['%env(HOME)%/src', '%env(HOME)%/src'];
        yield 'an environment placeholder with a processor' => ['%env(file:TOKEN)%', '%env(file:TOKEN)%'];
        yield 'an empty environment placeholder' => ['%env()%', '%%env()%%'];
        yield 'a name merely containing an environment call' => ['%my.env(HOME)%', '%%my.env(HOME)%%'];
        yield 'a name with text after the environment call' => ['%env(HOME)x%', '%%env(HOME)x%%'];
        yield 'an escaped percent' => ['/100%%/', '/100%%/'];
        yield 'an escaped pair' => ['%%x%%', '%%x%%'];
        yield 'a lone percent' => ['5% of it', '5% of it'];
        yield 'a pair spanning whitespace' => ['50% off 20%', '50% off 20%'];
        yield 'a known reference beside an unknown one' => ['%kernel.project_dir%/%x%', '%kernel.project_dir%/%%x%%'];
        yield 'two unknown pairs side by side' => ['%a%%b%', '%%a%%%%b%%'];
        yield 'no percent at all' => ['plain text', 'plain text'];
        yield 'nothing' => ['', ''];
    }

    #[DataProvider('readBackCases')]
    public function test_the_container_reads_an_escaped_unresolvable_value_back_as_written(string $value): void
    {
        $parameterBag = new ParameterBag(['text' => ContainerParameterSyntax::escapeUnresolvable($value, new ParameterBag())]);
        $parameterBag->resolve();

        self::assertSame($value, $parameterBag->get('text'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function readBackCases(): iterable
    {
        yield 'two pairs naming no parameter' => ['/sprintf\(.*%s.*%d/'];
        yield 'a range of percentages' => ['a discount between 50%-60% is fine'];
        yield 'two unknown pairs side by side' => ['%a%%b%'];
    }
}
