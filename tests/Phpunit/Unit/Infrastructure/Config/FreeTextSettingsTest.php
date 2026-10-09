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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\FreeTextSettings;

final class FreeTextSettingsTest extends TestCase
{
    private const string UNRESOLVABLE = 'between 50%-60% only';

    private const string ESCAPED = 'between 50%%-60%% only';

    /**
     * @param array<array-key, mixed> $config
     * @param array<array-key, mixed> $expected
     */
    #[DataProvider('configurations')]
    public function test_it_escapes_the_unresolvable_percent_pairs_of_the_free_text_settings_only(array $config, array $expected): void
    {
        self::assertSame($expected, FreeTextSettings::literalIn($config, new ParameterBag()));
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, array<array-key, mixed>}>
     */
    public static function configurations(): iterable
    {
        yield 'the regex of a risk pattern' => [
            ['scan' => ['custom_risk_patterns' => ['php' => ['sprintf_sql' => ['regex' => self::UNRESOLVABLE, 'description' => 'd']]]]],
            ['scan' => ['custom_risk_patterns' => ['php' => ['sprintf_sql' => ['regex' => self::ESCAPED, 'description' => 'd']]]]],
        ];
        yield 'the description of a risk pattern' => [
            ['scan' => ['custom_risk_patterns' => ['php' => ['sprintf_sql' => ['regex' => '/x/', 'description' => self::UNRESOLVABLE]]]]],
            ['scan' => ['custom_risk_patterns' => ['php' => ['sprintf_sql' => ['regex' => '/x/', 'description' => self::ESCAPED]]]]],
        ];
        yield 'every risk pattern of every bucket' => [
            ['scan' => ['custom_risk_patterns' => [
                'php' => ['a' => ['regex' => self::UNRESOLVABLE, 'description' => 'd'], 'b' => ['regex' => self::UNRESOLVABLE, 'description' => 'd']],
                'twig' => ['c' => ['regex' => self::UNRESOLVABLE, 'description' => 'd']],
            ]]],
            ['scan' => ['custom_risk_patterns' => [
                'php' => ['a' => ['regex' => self::ESCAPED, 'description' => 'd'], 'b' => ['regex' => self::ESCAPED, 'description' => 'd']],
                'twig' => ['c' => ['regex' => self::ESCAPED, 'description' => 'd']],
            ]]],
        ];
        yield 'every additional scrubbing pattern' => [
            ['scan' => ['secret_scrubbing' => ['enabled' => true, 'additional_patterns' => [self::UNRESOLVABLE, 'plain', self::UNRESOLVABLE]]]],
            ['scan' => ['secret_scrubbing' => ['enabled' => true, 'additional_patterns' => [self::ESCAPED, 'plain', self::ESCAPED]]]],
        ];
        yield 'the instructions of every custom skill' => [
            ['audit' => ['custom_skills' => [
                'pricing' => ['file_type' => 'controller', 'instructions' => self::UNRESOLVABLE, 'priority' => 5],
                'other' => ['file_type' => 'voter', 'instructions' => self::UNRESOLVABLE],
            ]]],
            ['audit' => ['custom_skills' => [
                'pricing' => ['file_type' => 'controller', 'instructions' => self::ESCAPED, 'priority' => 5],
                'other' => ['file_type' => 'voter', 'instructions' => self::ESCAPED],
            ]]],
        ];
        yield 'a setting that is not free text, even holding the same pair' => [
            ['cache' => ['dir' => self::UNRESOLVABLE], 'audit' => ['baseline' => self::UNRESOLVABLE, 'report_path_prefix' => self::UNRESOLVABLE], 'scan' => ['included_paths' => [self::UNRESOLVABLE]], 'model' => self::UNRESOLVABLE],
            ['cache' => ['dir' => self::UNRESOLVABLE], 'audit' => ['baseline' => self::UNRESOLVABLE, 'report_path_prefix' => self::UNRESOLVABLE], 'scan' => ['included_paths' => [self::UNRESOLVABLE]], 'model' => self::UNRESOLVABLE],
        ];
        yield 'a sibling of a free text setting' => [
            ['audit' => ['custom_skills' => ['pricing' => ['file_type' => self::UNRESOLVABLE, 'priority' => self::UNRESOLVABLE]]], 'scan' => ['custom_risk_patterns' => ['php' => ['a' => ['regex' => '/x/', 'other' => self::UNRESOLVABLE]]]]],
            ['audit' => ['custom_skills' => ['pricing' => ['file_type' => self::UNRESOLVABLE, 'priority' => self::UNRESOLVABLE]]], 'scan' => ['custom_risk_patterns' => ['php' => ['a' => ['regex' => '/x/', 'other' => self::UNRESOLVABLE]]]]],
        ];
        yield 'a free text setting at the wrong depth' => [
            ['scan' => ['custom_risk_patterns' => ['php' => ['regex' => self::UNRESOLVABLE], 'twig' => ['a' => ['b' => ['regex' => self::UNRESOLVABLE]]]]], 'audit' => ['custom_skills' => ['instructions' => self::UNRESOLVABLE]]],
            ['scan' => ['custom_risk_patterns' => ['php' => ['regex' => self::UNRESOLVABLE], 'twig' => ['a' => ['b' => ['regex' => self::UNRESOLVABLE]]]]], 'audit' => ['custom_skills' => ['instructions' => self::UNRESOLVABLE]]],
        ];
        yield 'a free text setting holding no string' => [
            ['scan' => ['custom_risk_patterns' => ['php' => ['a' => ['regex' => 5, 'description' => null]]], 'secret_scrubbing' => ['additional_patterns' => [true]]]],
            ['scan' => ['custom_risk_patterns' => ['php' => ['a' => ['regex' => 5, 'description' => null]]], 'secret_scrubbing' => ['additional_patterns' => [true]]]],
        ];
        yield 'an empty configuration' => [[], []];
    }

    public function test_it_leaves_a_reference_the_container_can_resolve_in_a_free_text_setting(): void
    {
        $config = ['audit' => ['custom_skills' => ['pricing' => ['file_type' => 'controller', 'instructions' => 'in %kernel.project_dir% and %env(HOME)% and 100%%']]]];

        self::assertSame($config, FreeTextSettings::literalIn($config, new ParameterBag(['kernel.project_dir' => '/srv/app'])));
    }

    public function test_it_escapes_against_the_parameters_it_is_given(): void
    {
        $config = ['audit' => ['custom_skills' => ['pricing' => ['file_type' => 'controller', 'instructions' => 'in %team.name%']]]];

        self::assertSame('in %%team.name%%', $this->instructionsOf(FreeTextSettings::literalIn($config, new ParameterBag())));
        self::assertSame('in %team.name%', $this->instructionsOf(FreeTextSettings::literalIn($config, new ParameterBag(['team.name' => 'platform']))));
    }

    /**
     * @param array<array-key, mixed> $config
     */
    private function instructionsOf(array $config): mixed
    {
        $audit = $config['audit'];
        self::assertIsArray($audit);
        $customSkills = $audit['custom_skills'];
        self::assertIsArray($customSkills);
        $pricing = $customSkills['pricing'];
        self::assertIsArray($pricing);

        return $pricing['instructions'];
    }
}
