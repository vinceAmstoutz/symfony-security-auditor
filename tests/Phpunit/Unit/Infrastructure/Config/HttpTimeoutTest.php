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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigUserOnlyKeyException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HttpTimeout;

final class HttpTimeoutTest extends TestCase
{
    private const string CONFIG_FILE = '/home/you/.config/symfony-security-auditor/config.yaml';

    private const string PROJECT_CONFIG_FILE = '/work/app/.symfony-security-auditor.yaml';

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_configuration_setting_none_waits_ten_minutes_for_the_provider(): void
    {
        self::assertSame(600.0, HttpTimeout::in(['model' => 'llama3.2'], self::CONFIG_FILE));
    }

    /**
     * @throws MalformedProjectConfigException
     */
    #[DataProvider('timeouts')]
    public function test_it_reads_the_seconds_the_configuration_sets(int|float $seconds, float $expected): void
    {
        self::assertSame($expected, HttpTimeout::in(['http_timeout' => $seconds], self::CONFIG_FILE));
    }

    /**
     * @return iterable<string, array{int|float, float}>
     */
    public static function timeouts(): iterable
    {
        yield 'whole seconds' => [1800, 1800.0];
        yield 'a fraction of a second' => [0.5, 0.5];
    }

    /**
     * @throws MalformedProjectConfigException
     */
    #[DataProvider('valuesThatAreNoTimeout')]
    public function test_it_refuses_a_value_that_is_no_number_of_seconds(mixed $value): void
    {
        $this->expectException(MalformedProjectConfigException::class);
        $this->expectExceptionMessage(\sprintf('Config file "%s" sets "http_timeout" to something other than a number of seconds above zero.', self::CONFIG_FILE));

        HttpTimeout::in(['http_timeout' => $value], self::CONFIG_FILE);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function valuesThatAreNoTimeout(): iterable
    {
        yield 'zero' => [0];
        yield 'a negative number' => [-30];
        yield 'infinity' => [\INF];
        yield 'text' => ['600'];
        yield 'nothing' => [null];
    }

    /**
     * @throws ProjectConfigUserOnlyKeyException
     */
    public function test_a_project_config_setting_no_timeout_leaves_the_user_one(): void
    {
        self::assertNull(HttpTimeout::raisedBy(['fail_on' => 'high'], 1200.0, self::PROJECT_CONFIG_FILE));
    }

    /**
     * @throws ProjectConfigUserOnlyKeyException
     */
    #[DataProvider('projectTimeoutsGivingAsMuchTime')]
    public function test_a_project_config_may_give_the_provider_as_much_time_or_more(int|float $seconds, float $expected): void
    {
        self::assertSame($expected, HttpTimeout::raisedBy(['http_timeout' => $seconds], 900.0, self::PROJECT_CONFIG_FILE));
    }

    /**
     * @return iterable<string, array{int|float, float}>
     */
    public static function projectTimeoutsGivingAsMuchTime(): iterable
    {
        yield 'it repeats the user timeout' => [900, 900.0];
        yield 'it raises it' => [1800.5, 1800.5];
    }

    /**
     * @param array<string, mixed> $projectConfig
     *
     * @throws ProjectConfigUserOnlyKeyException
     */
    #[DataProvider('projectTimeoutsGivingLessTime')]
    public function test_a_project_config_may_not_give_the_provider_less_time(array $projectConfig): void
    {
        $this->expectException(ProjectConfigUserOnlyKeyException::class);
        $this->expectExceptionMessage(\sprintf('The project config "%s" sets "http_timeout" to something other than a number of seconds at or above the timeout your user config allows — a repository you audit may give the provider more time, never less.', self::PROJECT_CONFIG_FILE));

        HttpTimeout::raisedBy($projectConfig, 900.0, self::PROJECT_CONFIG_FILE);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function projectTimeoutsGivingLessTime(): iterable
    {
        yield 'a shorter timeout' => [['http_timeout' => 899.5]];
        yield 'one that is no timeout at all' => [['http_timeout' => 'forever']];
        yield 'an infinite one' => [['http_timeout' => \INF]];
        yield 'none at all' => [['http_timeout' => 0]];
    }
}
