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

/**
 * What the recorded release wrote, read back by the tree under test: its
 * baselines (used, regenerated, merged and pruned), its JSON reports (by
 * `audit:diff`, `audit:trend` and `audit:baseline`) and its cache directory.
 * The release writes them while the scenario is prepared, and the recording
 * keeps them as artifacts.
 */
final readonly class ReportScenarios
{
    private const string BASELINE = '{workspace}/baseline.json';

    private const string EARLIER = '{workspace}/reports/earlier.json';

    private const string LATER = '{workspace}/reports/later.json';

    /**
     * @return list<Scenario>
     */
    public static function all(): array
    {
        return [...self::baselines(), ...self::reportCommands(), ...self::caches()];
    }

    /**
     * @return list<Scenario>
     */
    private static function baselines(): array
    {
        $scenario = self::base('baseline/generated-by-release')
            ->preparing(Step::audit(['--format' => 'json', '--generate-baseline' => self::BASELINE]))
            ->keepingArtifacts('baseline.json');

        return [
            $scenario->running(Step::audit(['--format' => 'json', '--baseline' => self::BASELINE])),
            $scenario->renamed('baseline/generated-by-release-sarif')->running(Step::audit(['--format' => 'sarif', '--baseline' => self::BASELINE])),
            $scenario->renamed('baseline/generated-by-release-console')->running(Step::audit(['--baseline' => self::BASELINE])),
            $scenario->renamed('baseline/generated-by-release-regenerated')
                ->running(Step::audit(['--format' => 'json', '--baseline' => self::BASELINE, '--generate-baseline' => '{workspace}/baseline-next.json']))
                ->collecting('baseline-next.json'),
            $scenario->renamed('baseline/generated-by-release-config-key')
                ->withConfig(['audit' => ['baseline' => self::BASELINE]])
                ->running(Step::audit(['--format' => 'json'])),
            $scenario->renamed('baseline/generated-by-release-on-changed-project')
                ->changingAfterPreparation(...self::fixedProject('project'))
                ->running(Step::audit(['--format' => 'json', '--baseline' => self::BASELINE])),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function reportCommands(): array
    {
        $scenario = self::base('report-commands/diff')
            ->withSetup(...self::fixedProject('project-later'))
            ->preparing(
                Step::audit(['--format' => 'json', '--output' => self::EARLIER]),
                new Step('audit:run', ['project-path' => '{workspace}/project-later', '--format' => 'json', '--output' => self::LATER]),
                new Step('audit:run', ['project-path' => '{workspace}/project-later', '--format' => 'json', '--output' => '{workspace}/reports/scoped.json', '--path' => ['src/Controller']]),
                Step::audit(['--format' => 'json', '--generate-baseline' => self::BASELINE]),
            )
            ->keepingArtifacts('reports', 'baseline.json');

        return [
            $scenario->running(new Step('audit:diff', ['previous-report' => self::EARLIER, 'current-report' => self::LATER])),
            $scenario->renamed('report-commands/diff-json')->running(new Step('audit:diff', ['previous-report' => self::EARLIER, 'current-report' => self::LATER, '--format' => 'json'])),
            $scenario->renamed('report-commands/diff-scoped-json')->running(new Step('audit:diff', ['previous-report' => self::EARLIER, 'current-report' => '{workspace}/reports/scoped.json', '--format' => 'json'])),
            $scenario->renamed('report-commands/diff-missing-report')->running(new Step('audit:diff', ['previous-report' => self::EARLIER, 'current-report' => '{workspace}/reports/none.json'])),
            $scenario->renamed('report-commands/trend')->running(new Step('audit:trend', ['reports' => [self::EARLIER, self::LATER]])),
            $scenario->renamed('report-commands/trend-json')->running(new Step('audit:trend', ['reports' => [self::EARLIER, self::LATER, '{workspace}/reports/scoped.json'], '--format' => 'json'])),
            $scenario->renamed('report-commands/trend-html')->running(new Step('audit:trend', ['reports' => [self::EARLIER, self::LATER], '--format' => 'html'])),
            $scenario->renamed('report-commands/trend-single-report')->running(new Step('audit:trend', ['reports' => [self::EARLIER]])),
            $scenario->renamed('report-commands/baseline-create')
                ->running(new Step('audit:baseline', ['report' => self::EARLIER, 'baseline' => '{workspace}/created.json']))
                ->collecting('created.json'),
            $scenario->renamed('report-commands/baseline-merge')
                ->running(new Step('audit:baseline', ['report' => self::LATER, 'baseline' => self::BASELINE]))
                ->collecting('baseline.json'),
            $scenario->renamed('report-commands/baseline-prune')
                ->running(new Step('audit:baseline', ['report' => self::LATER, 'baseline' => self::BASELINE, '--prune' => true]))
                ->collecting('baseline.json'),
            $scenario->renamed('report-commands/baseline-prune-scoped')
                ->running(new Step('audit:baseline', ['report' => '{workspace}/reports/scoped.json', 'baseline' => self::BASELINE, '--prune' => true]))
                ->collecting('baseline.json'),
            $scenario->renamed('report-commands/baseline-default-file')
                ->running((new Step('audit:baseline', ['report' => self::EARLIER]))->in('{workspace}'))
                ->collecting('.security-baseline.json'),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function caches(): array
    {
        $scenario = self::base('cache/written-by-release')
            ->withConfig(['cache' => ['enabled' => true, 'dir' => '{workspace}/shared-cache'], 'audit' => ['triage_memory' => true]])
            ->preparing(Step::audit(['--format' => 'json']))
            ->keepingArtifacts('shared-cache');

        return [
            $scenario->running(Step::audit(['--format' => 'json'])),
            $scenario->renamed('cache/written-by-release-no-cache')->running(Step::audit(['--format' => 'json', '--no-cache' => true])),
            $scenario->renamed('cache/written-by-release-changed-project')
                ->changingAfterPreparation(...self::fixedProject('project'))
                ->running(Step::audit(['--format' => 'json'])),
            self::base('cache/written-by-release-batch')
                ->withConfig(['cache' => ['enabled' => true, 'dir' => '{workspace}/shared-cache'], 'audit' => ['reviewer_batch_size' => 5, 'structured_collection' => false, 'reviewer_structured_collection' => false]])
                ->preparing(Step::audit(['--format' => 'json']))
                ->keepingArtifacts('shared-cache')
                ->running(Step::audit(['--format' => 'json'])),
        ];
    }

    private static function base(string $name): Scenario
    {
        return Scenario::bundle($name)->withProjectFiles(ProjectFixtures::base());
    }

    /**
     * The base project after a fix: the admin controller is guarded, and a new
     * controller brings a new finding.
     *
     * @return list<SetupActionInterface>
     */
    private static function fixedProject(string $directory): array
    {
        $actions = [];
        foreach (ProjectFixtures::base() as $path => $content) {
            $actions[] = new WriteFile(\sprintf('%s/%s', $directory, $path), $content);
        }

        return [
            ...$actions,
            new WriteFile(\sprintf('%s/src/Controller/AdminController.php', $directory), ProjectFixtures::controller('AdminController', ['guarded now'])),
            new WriteFile(\sprintf('%s/src/Controller/NewController.php', $directory), ProjectFixtures::controller('NewController', [ProjectFixtures::finding(['type' => 'ssrf', 'severity' => 'high', 'title' => 'New file ssrf', 'confidence' => 0.9, 'line_start' => 7])])),
        ];
    }
}
