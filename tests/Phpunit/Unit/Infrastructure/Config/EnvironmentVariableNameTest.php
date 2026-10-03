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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EnvironmentVariableName;

final class EnvironmentVariableNameTest extends TestCase
{
    #[DataProvider('validNames')]
    public function test_it_accepts_a_name_a_shell_can_export(string $name): void
    {
        self::assertTrue(EnvironmentVariableName::isValid($name));
        self::assertNull(EnvironmentVariableName::violationFor($name));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function validNames(): iterable
    {
        yield 'upper case with underscores' => ['ANTHROPIC_API_KEY'];
        yield 'lower case' => ['api_key'];
        yield 'leading underscore' => ['_KEY'];
        yield 'digits after the first character' => ['KEY2'];
        yield 'a single letter' => ['K'];
    }

    #[DataProvider('invalidNames')]
    public function test_it_refuses_a_name_no_placeholder_could_read_back(string $name): void
    {
        self::assertFalse(EnvironmentVariableName::isValid($name));
    }

    #[DataProvider('shownNames')]
    public function test_it_says_what_a_valid_name_looks_like(string $name, string $shown): void
    {
        self::assertSame(
            \sprintf('"%s" is not a valid environment variable name (letters, digits, and underscores only; must not start with a digit).', $shown),
            EnvironmentVariableName::violationFor($name),
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function shownNames(): iterable
    {
        yield 'a mistyped name as typed' => ['FOO-BAR', 'FOO-BAR'];
        yield 'a space as typed' => ['not a var', 'not a var'];
        yield 'empty' => ['', ''];
        yield 'the longest name shown as typed' => ['ANTHROPIC-API-KEY-SECRT', 'ANTHROPIC-API-KEY-SECRT'];
        yield 'a longer value, masked as the key it may be' => ['sk-ant-api03-pasted-into-env-var', 'sk-ant…-var'];
        yield 'a control byte escaped' => ["FOO\e[31m", 'FOO\\033[31m'];
        yield 'a non-UTF-8 byte escaped' => ["MY\xffKEY", 'MY\\377KEY'];
        yield 'a trailing newline escaped' => ["FOO\n", 'FOO\\n'];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidNames(): iterable
    {
        yield 'empty' => [''];
        yield 'starts with a digit' => ['123'];
        yield 'hyphen' => ['FOO-BAR'];
        yield 'space' => ['not a var'];
        yield 'dot' => ['generic.gateway'];
        yield 'env processor syntax' => ['file:KEY'];
        yield 'non-UTF-8 byte' => ["MY\xffKEY"];
        yield 'trailing newline' => ["FOO\n"];
    }
}
