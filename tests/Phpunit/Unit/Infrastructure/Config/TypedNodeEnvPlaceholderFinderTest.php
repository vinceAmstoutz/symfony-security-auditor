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
use Symfony\Component\DependencyInjection\ParameterBag\EnvPlaceholderParameterBag;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\TypedNodeEnvPlaceholderFinder;

final class TypedNodeEnvPlaceholderFinderTest extends TestCase
{
    /**
     * @param array<array-key, mixed> $config
     * @param list<string>            $expectedPaths
     */
    #[DataProvider('configurationsHoldingAPlaceholder')]
    public function test_it_names_every_setting_that_is_not_a_plain_string_and_holds_a_placeholder(array $config, array $expectedPaths): void
    {
        $envPlaceholderParameterBag = new EnvPlaceholderParameterBag();
        $placeholder = $envPlaceholderParameterBag->get('env(SSA_VALUE)');
        self::assertIsString($placeholder);

        self::assertSame($expectedPaths, (new TypedNodeEnvPlaceholderFinder())->pathsIn(self::fill($config, $placeholder), $envPlaceholderParameterBag));
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, list<string>}>
     */
    public static function configurationsHoldingAPlaceholder(): iterable
    {
        yield 'a float' => [['audit' => ['budget' => ['max_cost_usd' => null]]], ['symfony_security_auditor.audit.budget.max_cost_usd']];
        yield 'an integer' => [['audit' => ['min_score' => null]], ['symfony_security_auditor.audit.min_score']];
        yield 'a nullable integer' => [['audit' => ['rate_limit' => ['requests_per_minute' => null]]], ['symfony_security_auditor.audit.rate_limit.requests_per_minute']];
        yield 'a flag' => [['audit' => ['tools_enabled' => null]], ['symfony_security_auditor.audit.tools_enabled']];
        yield 'a flag in another section' => [['cache' => ['enabled' => null]], ['symfony_security_auditor.cache.enabled']];
        yield 'a choice read as a PHP enum' => [['audit' => ['fail_on' => null]], ['symfony_security_auditor.audit.fail_on']];
        yield 'the profile' => [['profile' => null], ['symfony_security_auditor.profile']];
        yield 'a number inside a keyed list' => [['audit' => ['custom_skills' => ['xss' => ['priority' => null]]]], ['symfony_security_auditor.audit.custom_skills.xss.priority']];
        yield 'a choice read as a PHP enum inside a keyed list' => [['audit' => ['custom_skills' => ['xss' => ['file_type' => null]]]], ['symfony_security_auditor.audit.custom_skills.xss.file_type']];
        yield 'a whole section' => [['audit' => null], ['symfony_security_auditor.audit']];
        yield 'a whole list' => [['scan' => ['included_paths' => null]], ['symfony_security_auditor.scan.included_paths']];
        yield 'two settings, in the order the configuration tree declares them' => [
            ['audit' => ['min_score' => null, 'fail_on' => null]],
            ['symfony_security_auditor.audit.fail_on', 'symfony_security_auditor.audit.min_score'],
        ];
        yield 'two entries of a keyed list, in the order given' => [
            ['audit' => ['custom_skills' => ['xss' => ['priority' => null], 'sqli' => ['priority' => null]]]],
            ['symfony_security_auditor.audit.custom_skills.xss.priority', 'symfony_security_auditor.audit.custom_skills.sqli.priority'],
        ];
    }

    /**
     * @param array<array-key, mixed> $config
     */
    #[DataProvider('configurationsHoldingAPlaceholderTheContainerResolves')]
    public function test_it_lets_a_placeholder_through_on_a_setting_kept_as_text(array $config): void
    {
        $envPlaceholderParameterBag = new EnvPlaceholderParameterBag();
        $placeholder = $envPlaceholderParameterBag->get('env(SSA_VALUE)');
        self::assertIsString($placeholder);

        self::assertSame([], (new TypedNodeEnvPlaceholderFinder())->pathsIn(self::fill($config, $placeholder), $envPlaceholderParameterBag));
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function configurationsHoldingAPlaceholderTheContainerResolves(): iterable
    {
        yield 'the model' => [['model' => null]];
        yield 'a nested string' => [['audit' => ['escalation' => ['cheap_model' => null]]]];
        yield 'a list of strings' => [['scan' => ['included_paths' => [null]]]];
        yield 'a choice kept as text' => [['audit' => ['format' => null]]];
        yield 'a list of choices kept as text' => [['audit' => ['excluded_types' => [null]]]];
    }

    /**
     * @param array<array-key, mixed> $config
     */
    #[DataProvider('configurationsNoTreeCouldHold')]
    public function test_it_ignores_a_value_that_is_neither_text_nor_a_list_where_the_tree_expects_one(array $config): void
    {
        self::assertSame([], (new TypedNodeEnvPlaceholderFinder())->pathsIn($config, new EnvPlaceholderParameterBag()));
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function configurationsNoTreeCouldHold(): iterable
    {
        yield 'a number where a section is expected' => [['audit' => 5]];
        yield 'a list where text is expected' => [['model' => ['gpt-5.6']]];
    }

    public function test_it_ignores_a_string_that_only_looks_like_a_placeholder(): void
    {
        $envPlaceholderParameterBag = new EnvPlaceholderParameterBag();
        $prefix = $envPlaceholderParameterBag->getEnvPlaceholderUniquePrefix();

        self::assertSame([], (new TypedNodeEnvPlaceholderFinder())->pathsIn(['audit' => ['fail_on' => substr($prefix, 0, -1)]], $envPlaceholderParameterBag));
    }

    public function test_it_finds_nothing_when_the_container_resolves_no_environment_variable(): void
    {
        self::assertSame([], (new TypedNodeEnvPlaceholderFinder())->pathsIn(['audit' => ['min_score' => 'env_0123456789abcdef_SSA_VALUE_fedcba9876543210']], new ParameterBag()));
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    private static function fill(array $config, string $placeholder): array
    {
        return array_map(
            static fn (mixed $value): mixed => \is_array($value) ? self::fill($value, $placeholder) : $placeholder,
            $config,
        );
    }
}
