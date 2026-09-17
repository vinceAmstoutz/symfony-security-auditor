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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ContainerParameterSyntax;

final class ContainerParameterSyntaxTest extends TestCase
{
    #[DataProvider('valueCases')]
    public function test_it_rejects_a_value_the_container_would_read_as_a_parameter(string $value, bool $expected): void
    {
        self::assertSame($expected, ContainerParameterSyntax::accepts($value));
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
        yield 'an env placeholder with a suffix is not the whole value' => ['%env(GATEWAY_URL)%/v1', false];
    }
}
