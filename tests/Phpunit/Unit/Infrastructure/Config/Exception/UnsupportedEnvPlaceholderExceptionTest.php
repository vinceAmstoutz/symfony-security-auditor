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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config\Exception;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EnvPlaceholder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsupportedEnvPlaceholderException;

final class UnsupportedEnvPlaceholderExceptionTest extends TestCase
{
    private const string PASTED_KEY = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789';

    public function test_it_names_the_env_processor_the_binary_does_not_apply(): void
    {
        self::assertSame(
            'The placeholder "%env(trim:API_KEY)%" applies an env processor, and the standalone binary applies none (trim:, string:, default:, …): it reads only "%env(VAR)%" and "%env(file:VAR)%", so name the variable directly — "%env(VAR)%" rather than "%env(trim:VAR)%".',
            $this->messageFor('%env(trim:API_KEY)%'),
        );
    }

    public function test_it_explains_the_name_rule_when_no_processor_is_involved(): void
    {
        self::assertSame(
            'The placeholder "%env(1PASSWORD_KEY)%" names no variable a shell can export: "1PASSWORD_KEY" is not a valid environment variable name (letters, digits, and underscores only; must not start with a digit). The standalone binary reads only "%env(VAR)%" and "%env(file:VAR)%".',
            $this->messageFor('%env(1PASSWORD_KEY)%'),
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function placeholdersAsQuoted(): iterable
    {
        yield 'a file placeholder keeps its prefix' => ['%env(file:trim:API_KEY)%', '"%env(file:trim:API_KEY)%"'];
        yield 'a chained processor keeps every segment' => ['%env(default::ANTHROPIC_API_KEY)%', '"%env(default::ANTHROPIC_API_KEY)%"'];
        yield 'a file placeholder naming no variable' => ['%env(file:)%', '"%env(file:)%"'];
    }

    #[DataProvider('placeholdersAsQuoted')]
    public function test_it_quotes_the_placeholder_so_its_line_can_be_found(string $placeholder, string $quoted): void
    {
        self::assertStringStartsWith(\sprintf('The placeholder %s ', $quoted), $this->messageFor($placeholder));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function pastedKeys(): iterable
    {
        yield 'a key pasted as the variable name' => ['%env('.self::PASTED_KEY.')%'];
        yield 'a key pasted behind a processor' => ['%env(trim:'.self::PASTED_KEY.')%'];
        yield 'a key pasted in front of a processor' => ['%env('.self::PASTED_KEY.':API_KEY)%'];
        yield 'a key pasted into a file placeholder' => ['%env(file:'.self::PASTED_KEY.')%'];
    }

    #[DataProvider('pastedKeys')]
    public function test_it_never_echoes_a_key_pasted_into_the_placeholder(string $placeholder): void
    {
        $message = $this->messageFor($placeholder);

        self::assertStringNotContainsString(self::PASTED_KEY, $message);
        self::assertStringNotContainsString('abcdefghijklmnop', $message);
    }

    public function test_it_never_echoes_a_key_whose_colons_split_it_into_short_segments(): void
    {
        $message = $this->messageFor('%env(3f9a0c1b2d3e4f5a6b7c:c2e7f8a9b0c1d2e3f4a5)%');

        self::assertStringNotContainsString('3f9a0c1b2d3e4f5a6b7c', $message);
        self::assertStringNotContainsString('c2e7f8a9b0c1d2e3f4a5', $message);
    }

    public function test_it_masks_a_long_placeholder_whose_segments_are_not_all_env_processors(): void
    {
        self::assertStringNotContainsString('app.fallback_key', $this->messageFor('%env(default:app.fallback_key:API_KEY)%'));
    }

    public function test_it_masks_a_short_pair_split_on_its_colon_entirely(): void
    {
        self::assertStringStartsWith('The placeholder "%env(…)%" ', $this->messageFor('%env(admin:hunter2pass)%'));
    }

    public function test_it_escapes_control_and_non_ascii_bytes_instead_of_sending_them_to_the_terminal(): void
    {
        $message = $this->messageFor("%env(trim:A\x1b[2J\x9bB)%");

        self::assertStringStartsWith('The placeholder "%env(trim:A\033[2J\233B)%" ', $message);
        self::assertStringNotContainsString("\x1b", $message);
        self::assertStringNotContainsString("\x9b", $message);
    }

    private function messageFor(string $placeholder): string
    {
        $envPlaceholder = EnvPlaceholder::in($placeholder);
        self::assertInstanceOf(EnvPlaceholder::class, $envPlaceholder);

        return UnsupportedEnvPlaceholderException::forPlaceholder($envPlaceholder)->getMessage();
    }
}
