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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EnvPlaceholder;

final class EnvPlaceholderTest extends TestCase
{
    public function test_it_names_the_variable_a_placeholder_points_at(): void
    {
        self::assertSame('ANTHROPIC_API_KEY', EnvPlaceholder::in('%env(ANTHROPIC_API_KEY)%')?->variableName);
    }

    public function test_it_treats_a_plain_placeholder_as_reading_the_environment(): void
    {
        self::assertFalse(EnvPlaceholder::in('%env(ANTHROPIC_API_KEY)%')?->readsFile);
    }

    public function test_it_names_the_variable_a_file_placeholder_points_at(): void
    {
        self::assertSame('ANTHROPIC_API_KEY_FILE', EnvPlaceholder::in('%env(file:ANTHROPIC_API_KEY_FILE)%')?->variableName);
    }

    public function test_it_treats_a_file_placeholder_as_reading_a_file(): void
    {
        self::assertTrue(EnvPlaceholder::in('%env(file:ANTHROPIC_API_KEY_FILE)%')?->readsFile);
    }

    #[DataProvider('valuesThatAreNotPlaceholders')]
    public function test_it_finds_no_placeholder_in_a_plain_value(string $value): void
    {
        self::assertNull(EnvPlaceholder::in($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function valuesThatAreNotPlaceholders(): iterable
    {
        yield 'a literal key' => ['anthropic-test-key-literal'];
        yield 'an unterminated placeholder' => ['%env(ANTHROPIC_API_KEY'];
        yield 'a placeholder with text around it' => ['prefix %env(ANTHROPIC_API_KEY)%'];
        yield 'an empty value' => [''];
    }
}
