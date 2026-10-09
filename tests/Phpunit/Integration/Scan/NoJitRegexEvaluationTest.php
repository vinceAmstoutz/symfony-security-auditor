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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Scan;

use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

final class NoJitRegexEvaluationTest extends TestCase
{
    private const float TIMEOUT_SECONDS = 1.0;

    /**
     * @param array<mixed> $expected
     *
     * @throws JsonException
     */
    #[DataProvider('hostileLineCases')]
    public function test_one_long_line_is_evaluated_in_linear_time_without_pcre_jit(string $case, array $expected): void
    {
        $process = new Process(
            [\PHP_BINARY, '-d', 'pcre.jit=0', __DIR__.'/Fixture/scan_hostile_line.php', $case],
            null,
            null,
            null,
            self::TIMEOUT_SECONDS,
        );

        try {
            $process->mustRun();
        } catch (ProcessTimedOutException) {
            self::fail(\sprintf('"%s" did not finish within %.1f s without PCRE JIT.', $case, self::TIMEOUT_SECONDS));
        }

        self::assertSame($expected, json_decode($process->getOutput(), true, 512, \JSON_THROW_ON_ERROR));
    }

    /** @return iterable<string, array{0: string, 1: array<mixed>}> */
    public static function hostileLineCases(): iterable
    {
        yield 'a line repeating include' => ['dynamic_file_inclusion', ['dynamic_file_inclusion@3']];
        yield 'a line repeating a LiveProp attribute' => ['live_prop_writable', ['live_prop_writable@4']];
        yield 'a line repeating supports()' => ['supports_returns_null', ['supports_returns_null@4']];
        yield 'a line repeating trusted_proxies' => ['trusted_proxies_wildcard', ['trusted_proxies_wildcard@2']];
        yield 'a line repeating forced_ssl' => ['hsts_disabled', ['hsts_disabled@2']];
        yield 'a line repeating ldap_search' => ['ldap_search', ['ldap_unescaped_filter_concat@3']];
        yield 'a string literal left open' => ['string_literal', ['xxxxx', 36007]];
        yield 'a line of empty block comments' => ['block_comment', ['line' => 'code', 'inside_block_comment' => false]];
        yield 'a line of block comments between escaped quotes' => ['block_comment_after_escaped_quote', ['line' => str_repeat("\\'", 30000).'code', 'inside_block_comment' => false]];
    }
}
