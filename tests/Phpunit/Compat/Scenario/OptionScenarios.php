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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner\Workspace;

/**
 * Every option of `audit:run` given alone, the nine formats on stdout and
 * written to a file, each exit code, and the gate values around their
 * bounds, on the bundle's console.
 */
final readonly class OptionScenarios
{
    private const array FORMATS = ['console' => 'txt', 'executive' => 'txt', 'json' => 'json', 'sarif' => 'sarif', 'html' => 'html', 'markdown' => 'md', 'junit' => 'xml', 'github' => 'txt', 'github-comment' => 'md'];

    /**
     * @return list<Scenario>
     */
    public static function all(): array
    {
        return [...self::formats(), ...self::outputs(), ...self::options(), ...self::gates()];
    }

    /**
     * @return list<Scenario>
     */
    private static function formats(): array
    {
        $scenarios = [];
        foreach (self::FORMATS as $format => $extension) {
            $scenarios[] = self::base(\sprintf('format/%s', $format), Step::audit(['--format' => $format]));
            $scenarios[] = self::base(\sprintf('format/%s-to-file', $format), Step::audit(['--format' => $format, '--output' => \sprintf('{workspace}/out/report.%s', $extension)]))
                ->collecting(\sprintf('out/report.%s', $extension));
            $scenarios[] = self::clean(\sprintf('format/%s-no-finding', $format), Step::audit(['--format' => $format]));
        }

        $scenarios[] = self::base('format/short-option', Step::audit(['-f' => 'json']));
        $scenarios[] = self::base('format/unknown', Step::audit(['--format' => 'yaml']));
        $scenarios[] = self::base('format/config-key', Step::audit())->withConfig(['audit' => ['format' => 'json']]);
        $scenarios[] = self::incomplete('format/sarif-incomplete-run', Step::audit(['--format' => 'sarif']));
        $scenarios[] = self::incomplete('format/github-incomplete-run', Step::audit(['--format' => 'github']));

        return $scenarios;
    }

    /**
     * @return list<Scenario>
     */
    private static function outputs(): array
    {
        return [
            self::base('output/relative-path', Step::audit(['--format' => 'json', '--output' => 'report.json']))->collecting('project/report.json'),
            self::base('output/short-option', Step::audit(['--format' => 'json', '-o' => '{workspace}/out/report.json']))->collecting('out/report.json'),
            self::base('output/dev-null', Step::audit(['--format' => 'json', '--output' => Workspace::NULL_DEVICE])),
            self::base('output/missing-directory', Step::audit(['--format' => 'json', '--output' => '{workspace}/missing/deeper/report.json']))->collecting('missing/deeper/report.json'),
            self::base('output/existing-file', Step::audit(['--format' => 'json', '--output' => '{workspace}/out/report.json']))
                ->withFiles(['out/report.json' => 'previous content'])
                ->collecting('out/report.json'),
            self::base('output/directory', Step::audit(['--format' => 'json', '--output' => '{workspace}/out']))->withFiles(['out/keep' => 'x']),
            self::base('output/config-key', Step::audit(['--format' => 'json']))->withConfig(['audit' => ['output' => '{workspace}/out/configured.json']])->collecting('out/configured.json'),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function options(): array
    {
        $cached = ['cache' => ['enabled' => true, 'dir' => '{workspace}/shared-cache']];

        return [
            self::base('option/project-path-only', Step::audit()),
            self::base('option/project-path-omitted', new Step('audit:run')),
            self::base('option/project-path-relative', new Step('audit:run', ['project-path' => 'project', '--format' => 'json'], '{workspace}')),
            self::base('option/project-path-missing', new Step('audit:run', ['project-path' => '{workspace}/nope', '--format' => 'json'])),
            self::base('option/alias', new Step('audit', ['project-path' => '{project}', '--format' => 'json'])),
            self::base('option/dry-run', Step::audit(['--dry-run' => true])),
            self::base('option/dry-run-json', Step::audit(['--dry-run' => true, '--format' => 'json'])),
            self::base('option/show-scanned', Step::audit(['--show-scanned' => true])),
            self::base('option/show-scanned-dry-run', Step::audit(['--show-scanned' => true, '--dry-run' => true])),
            self::base('option/no-cache', Step::audit(['--format' => 'json']), Step::audit(['--format' => 'json']), Step::audit(['--format' => 'json', '--no-cache' => true]))->withConfig($cached),
            self::base('option/path-short', Step::audit(['--format' => 'json', '-p' => ['src/Controller']])),
            self::base('option/since-without-git', Step::audit(['--format' => 'json', '--since' => 'HEAD'])),
            self::base('option/baseline-missing-file', Step::audit(['--format' => 'json', '--baseline' => '{workspace}/none.json'])),
            self::base('option/baseline-malformed-file', Step::audit(['--format' => 'json', '--baseline' => '{workspace}/baseline.json']))->withFiles(['baseline.json' => '{not json']),
            self::base('option/generate-baseline', Step::audit(['--format' => 'json', '--generate-baseline' => '{workspace}/baseline.json']))->collecting('baseline.json'),
            self::base('option/generate-baseline-console', Step::audit(['--generate-baseline' => '{workspace}/baseline.json']))->collecting('baseline.json'),
            self::base('option/fail-on-incomplete', Step::audit(['--format' => 'json', '--fail-on-incomplete' => true])),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function gates(): array
    {
        $scenarios = [];
        foreach (['safe', 'low', 'medium', 'high', 'critical', 'bogus'] as $level) {
            $scenarios[] = self::base(\sprintf('gate/fail-on-%s', $level), Step::audit(['--format' => 'json', '--fail-on' => $level]));
        }

        $scenarios[] = self::base('gate/fail-on-upper-case-high', Step::audit(['--format' => 'json', '--fail-on' => 'HIGH']));
        $scenarios[] = self::incomplete('gate/incomplete-run', Step::audit(['--format' => 'json']));
        $scenarios[] = self::incomplete('gate/incomplete-run-fail-on-incomplete', Step::audit(['--format' => 'json', '--fail-on-incomplete' => true]));
        $scenarios[] = self::incomplete('gate/incomplete-run-config-fail-on-incomplete', Step::audit(['--format' => 'json']))->withConfig(['audit' => ['fail_on_incomplete' => true]]);

        foreach (['-5', '0', '80', '81', '82', '100', '101', '150', '81.5', 'abc'] as $score) {
            $scenarios[] = self::base(\sprintf('gate/min-score-%s', $score), Step::audit(['--format' => 'json', '--min-score' => $score]));
        }

        foreach (['low', 'critical'] as $level) {
            $scenarios[] = self::base(\sprintf('gate/config-fail-on-%s', $level), Step::audit(['--format' => 'json']))->withConfig(['audit' => ['fail_on' => $level]]);
        }

        $scenarios[] = self::base('gate/config-min-score', Step::audit(['--format' => 'json']))->withConfig(['audit' => ['min_score' => 90]]);
        $scenarios[] = self::base('gate/config-fail-on-incomplete', Step::audit(['--format' => 'json']))->withConfig(['audit' => ['fail_on_incomplete' => true]]);
        $scenarios[] = self::base('gate/fail-on-and-min-score', Step::audit(['--format' => 'json', '--fail-on' => 'critical', '--min-score' => '90']));
        $scenarios[] = self::clean('gate/no-finding-min-score-100', Step::audit(['--format' => 'json', '--min-score' => '100']));

        return $scenarios;
    }

    private static function base(string $name, Step ...$steps): Scenario
    {
        return Scenario::bundle($name)->withProjectFiles(ProjectFixtures::base())->running(...$steps);
    }

    private static function incomplete(string $name, Step ...$steps): Scenario
    {
        return Scenario::bundle($name)->withProjectFiles(ProjectFixtures::incomplete())->running(...$steps);
    }

    private static function clean(string $name, Step ...$steps): Scenario
    {
        return Scenario::bundle($name)->withProjectFiles(ProjectFixtures::clean())->running(...$steps);
    }
}
