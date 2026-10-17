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

use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform\CountingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform\CustomLlmClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform\PlatformScript;

/**
 * `audit:run` of an application with the bundle, one behaviour each: the
 * collection modes, profiles, filters, iterations and deduplication, the
 * scan scope, `--since` and `--path`, budgets and provider failures, the
 * caches, escalation, how sloppy model answers are read, and an
 * application's own client and stage.
 */
final readonly class AuditRunScenarios
{
    private const array JSON = ['--format' => 'json'];

    /**
     * @return list<Scenario>
     */
    public static function all(): array
    {
        return [
            ...self::pipelineModes(),
            ...self::findingHandling(),
            ...self::scanScope(),
            ...self::sinceAndPath(),
            ...self::failures(),
            ...self::modelAnswers(),
            ...self::extensions(),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function pipelineModes(): array
    {
        $base = self::base('run/base');
        $jsonCollection = ['structured_collection' => false, 'reviewer_structured_collection' => false];

        return [
            $base,
            $base->renamed('run/json-collection')->withConfig(['audit' => $jsonCollection]),
            $base->renamed('run/reviewer-batch')->withConfig(['audit' => ['reviewer_batch_size' => 5]]),
            $base->renamed('run/reviewer-batch-json')->withConfig(['audit' => ['reviewer_batch_size' => 5, ...$jsonCollection]]),
            $base->renamed('run/profile-fast')->withConfig(['profile' => 'fast']),
            $base->renamed('run/profile-balanced')->withConfig(['profile' => 'balanced']),
            $base->renamed('run/profile-thorough')->withConfig(['profile' => 'thorough']),
            $base->renamed('run/concurrent')->withConfig(['audit' => ['attacker_max_concurrent' => 4, 'reviewer_max_concurrent' => 4]]),
            $base->renamed('run/concurrent-json')->withConfig(['audit' => ['attacker_max_concurrent' => 4, 'reviewer_max_concurrent' => 4, ...$jsonCollection]]),
            $base->renamed('run/tools-disabled')->withConfig(['audit' => ['tools_enabled' => false]]),
            $base->renamed('run/reviewer-tools')->withConfig(['audit' => ['reviewer_tools_enabled' => true]]),
            $base->renamed('run/chunking-type')->withConfig(['audit' => ['chunking' => ['strategy' => 'type']]]),
            $base->renamed('run/prescan-off')->withConfig(['audit' => ['static_prescan' => ['enabled' => false], 'code_slicing' => ['enabled' => false]]]),
            $base->renamed('run/poc-and-fix')->withConfig(['audit' => ['poc_synthesis' => ['enabled' => true], 'fix_synthesis' => ['enabled' => true, 'severity_floor' => 'medium']]]),
            $base->renamed('run/split-models')->withConfig(['attacker_model' => 'gpt-4.1', 'reviewer_model' => 'gpt-4o-mini']),
            $base->renamed('run/escalation-default')->withConfig(['audit' => ['escalation' => ['enabled' => true, 'cheap_model' => 'gpt-4o-mini']]]),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function findingHandling(): array
    {
        $base = self::base('run/base');

        return [
            $base->renamed('run/min-confidence')->withConfig(['audit' => ['min_confidence' => 0.7]]),
            $base->renamed('run/excluded-types')->withConfig(['audit' => ['excluded_types' => ['sql_injection', 'twig_injection']]]),
            $base->renamed('run/included-types')->withConfig(['audit' => ['included_types' => ['sql_injection', 'twig_injection']]]),
            $base->renamed('run/iterations-reviewer-sequence')
                ->withConfig(['audit' => ['max_iterations' => 3]])
                ->withPlatform(PlatformScript::default()->withReviewerSequence('Unprotected admin', [['adjusted_severity' => 'high'], ['adjusted_severity' => 'low'], ['adjusted_severity' => 'critical']])),
            $base->renamed('run/iterations')->withConfig(['audit' => ['max_iterations' => 3]]),
            self::single('run/dedupe-overlapping', 'D', [
                ['type' => 'sql_injection', 'severity' => 'high', 'title' => 'First', 'confidence' => 0.7, 'line_start' => 7, 'line_end' => 9],
                ['type' => 'sql_injection', 'severity' => 'critical', 'title' => 'Second overlapping', 'confidence' => 0.9, 'line_start' => 8, 'line_end' => 10],
                ['type' => 'sql_injection', 'severity' => 'high', 'title' => 'First', 'confidence' => 0.95, 'line_start' => 7, 'line_end' => 9],
                ['type' => 'ssrf', 'severity' => 'low', 'title' => 'Other type', 'confidence' => 0.9, 'line_start' => 8, 'line_end' => 9],
            ]),
            self::single('run/dedupe-same-id', 'E', [
                ['type' => 'sql_injection', 'severity' => 'high', 'title' => 'Same', 'confidence' => 0.7, 'line_start' => 7],
                ['type' => 'sql_injection', 'severity' => 'high', 'title' => 'Same', 'confidence' => 0.9, 'line_start' => 7],
                ['type' => 'sql_injection', 'severity' => 'critical', 'title' => 'Same', 'confidence' => 0.5, 'line_start' => 7],
            ]),
            self::single('run/iterations-overlap', 'X', [
                ['iter' => 1, 'type' => 'sql_injection', 'severity' => 'high', 'title' => 'Iteration one', 'confidence' => 0.8, 'line_start' => 7, 'line_end' => 9],
                ['iter' => 2, 'type' => 'sql_injection', 'severity' => 'critical', 'title' => 'Iteration two wider', 'confidence' => 0.9, 'line_start' => 6, 'line_end' => 10],
                ['iter' => 3, 'type' => 'sql_injection', 'severity' => 'low', 'title' => 'Iteration three lower', 'confidence' => 0.99, 'line_start' => 7, 'line_end' => 8],
            ])->withConfig(['audit' => ['max_iterations' => 3]]),
            self::escalation(),
            self::pathSpellings('run/finding-path-spellings'),
            Scenario::bundle('run/finding-absolute-path')
                ->withProjectFiles(['src/Controller/AdminController.php' => ProjectFixtures::controller('AdminController', [ProjectFixtures::finding(['file_path' => '{project}/src/Controller/AdminController.php', 'type' => 'broken_access_control', 'severity' => 'critical', 'title' => 'absolute', 'confidence' => 0.95, 'line_start' => 7])])])
                ->running(Step::audit(self::JSON)),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function scanScope(): array
    {
        $scenario = self::base('run/scan-layout')->withConfig(['scan' => ['max_file_size_kb' => 1]])->withSetup(...self::scanLayout());

        return [
            $scenario,
            $scenario->renamed('run/scan-layout-no-gitignore')->withConfig(['scan' => ['max_file_size_kb' => 1024, 'respect_gitignore' => false]]),
            $scenario->renamed('run/scan-layout-included-paths')->withConfig(['scan' => ['included_paths' => ['src', 'config', 'templates', 'public', 'migrations', 'tests', '.env', 'composer.json'], 'max_file_size_kb' => 512]]),
            $scenario->renamed('run/scan-layout-git')
                ->withConfig(['scan' => ['max_file_size_kb' => 512]])
                ->withFiles(['project/.gitignore' => "var/\nsrc/Ignored/\n*.log\nsrc/Kernel.php\n"])
                ->withSetup(new GitCommit(['src/Kernel.php'])),
            $scenario->renamed('run/scan-layout-formats')->withoutSteps()->running(
                ...array_map(static fn (string $format): Step => Step::audit(['--format' => $format]), ['console', 'executive', 'sarif', 'html', 'markdown', 'junit', 'github', 'github-comment']),
                ...[Step::audit([...self::JSON, '--fail-on-incomplete' => true]), Step::audit([...self::JSON, '--fail-on' => 'low']), Step::audit([...self::JSON, '--min-score' => '99'])],
            ),
            Scenario::bundle('run/empty-project')->withProjectFiles(['README.md' => 'x'])->running(Step::audit(self::JSON)),
            Scenario::bundle('run/empty-project-console')->withProjectFiles(['README.md' => 'x'])->running(Step::audit()),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function sinceAndPath(): array
    {
        $scenario = self::base('run/since')->withSetup(...self::changedAfterCommit())->withoutSteps()->running(Step::audit([...self::JSON, '--since' => 'HEAD']));
        $base = self::base('run/base');
        $scenarios = [
            $scenario,
            $scenario->renamed('run/since-tools')
                ->withConfig(['audit' => ['attacker_max_concurrent' => 1]])
                ->withPlatform(PlatformScript::default()
                    ->withAttackerToolCall('read_file', ['path' => 'src/Controller/UserController.php'])
                    ->withAttackerToolCall('read_file', ['path' => 'src/Controller/AdminController.php'])
                    ->withAttackerToolCall('grep', ['pattern' => 'DOWNGRADE'])
                    ->withAttackerToolCall('list_files', [])),
            $base->renamed('run/path-directory')->withoutSteps()->running(Step::audit([...self::JSON, '--path' => ['src/Controller']])),
            $base->renamed('run/path-file-and-directory')->withoutSteps()->running(Step::audit([...self::JSON, '--path' => ['src/Controller/AdminController.php', 'templates']])),
            $base->renamed('run/path-outside-included-paths')
                ->withConfig(['scan' => ['included_paths' => ['src']]])
                ->withProjectFiles(['lib/Extra.php' => "<?php // outside included\n"])
                ->withoutSteps()->running(Step::audit([...self::JSON, '--path' => ['lib']])),
            $base->renamed('run/path-spelled-with-dot-and-backslash')->withoutSteps()->running(Step::audit([...self::JSON, '--path' => ['./src/Controller/', 'src\Service']])),
            $base->renamed('run/path-missing')->withoutSteps()->running(Step::audit([...self::JSON, '--path' => ['nope']])),
            $base->renamed('run/path-secret-files')
                ->withProjectFiles(['deploy/notes.txt' => "internal runbook: staging admin password is hunter2-not-a-pattern\n", 'docker-compose.yml' => "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: s3cretpw\n"])
                ->withoutSteps()->running(Step::audit([...self::JSON, '--path' => ['deploy/notes.txt', 'docker-compose.yml']])),
        ];

        foreach (['dot' => ['.'], 'dot-slash' => ['./'], 'empty' => [''], 'mixed' => ['src/Controller', '.'], 'whitespace' => [' src/Controller '], 'upper-case' => ['SRC/Controller'], 'file' => ['composer.json'], 'tilde' => ['~'], 'glob' => ['src/*'], 'dot-dot' => ['src/../templates'], 'overlapping' => ['src', 'src/Controller']] as $name => $paths) {
            $scenarios[] = $base->renamed(\sprintf('run/path-%s', $name))->withoutSteps()->running(Step::audit([...self::JSON, '--path' => $paths]));
        }

        return $scenarios;
    }

    /**
     * @return list<Scenario>
     */
    private static function failures(): array
    {
        $base = self::base('run/base');

        return [
            $base->renamed('run/budget-tokens-exceeded')->withConfig(['audit' => ['budget' => ['max_tokens' => 450]]]),
            $base->renamed('run/budget-cost-exceeded')->withConfig(['audit' => ['budget' => ['max_cost_usd' => 0.0001]]]),
            $base->renamed('run/budget-within')->withConfig(['audit' => ['budget' => ['max_tokens' => 100000, 'max_cost_usd' => 5]]]),
            $base->renamed('run/budget-unpriced-model')->withConfig(['model' => 'compat-unpriced-model', 'audit' => ['budget' => ['max_cost_usd' => 5]]]),
            $base->renamed('run/rate-limited')->withConfig(['audit' => ['rate_limit' => ['requests_per_minute' => 6000, 'input_tokens_per_minute' => 10000000, 'output_tokens_per_minute' => 1000000]]]),
            $base->renamed('run/provider-error')->withPlatform(PlatformScript::default()->failingAfter(3, 'HTTP 500 Internal Server Error')),
            $base->renamed('run/provider-unauthorized')->withPlatform(PlatformScript::default()->failingAfter(0, 'HTTP 401 Unauthorized invalid x-api-key')),
            $base->renamed('run/provider-retried')
                ->withPlatform(PlatformScript::default()->failingAfter(2, 'HTTP 503 Service Unavailable'))
                ->withConfig(['audit' => ['retry' => ['max_attempts' => 2, 'initial_delay_ms' => 1]]]),
            $base->renamed('run/provider-error-fail-on-incomplete')
                ->withPlatform(PlatformScript::default()->failingAfter(3, 'HTTP 500 Internal Server Error'))
                ->withoutSteps()->running(Step::audit([...self::JSON, '--fail-on-incomplete' => true])),
            $base->renamed('run/cache-cold')->withConfig(['cache' => ['enabled' => true, 'dir' => '{workspace}/shared-cache'], 'audit' => ['triage_memory' => true]]),
            $base->renamed('run/cache-cold-batch')->withConfig(['cache' => ['enabled' => true, 'dir' => '{workspace}/shared-cache'], 'audit' => ['reviewer_batch_size' => 5, 'structured_collection' => false, 'reviewer_structured_collection' => false]]),
            $base->renamed('run/advisory-lookup')
                ->withProjectFiles(['composer.lock' => (string) json_encode(['packages' => [['name' => 'symfony/http-kernel', 'version' => 'v5.4.0'], ['name' => 'twig/twig', 'version' => 'v3.0.0']], 'packages-dev' => []])])
                ->withPlatform(PlatformScript::default()
                    ->withAttackerToolCall('lookup_advisory', ['package' => 'symfony/http-kernel', 'version' => '5.4.0'])
                    ->withAttackerToolCall('lookup_advisory', ['package' => 'nonexistent/pkg', 'version' => '1.0.0'])),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function modelAnswers(): array
    {
        $files = [];
        $verdicts = PlatformScript::default();
        foreach (['T_true' => true, 'T_false' => false, 'T_str_false' => 'false', 'T_str_no' => 'no', 'T_str_yes' => 'yes', 'T_str_rejected' => 'rejected', 'T_int1' => 1, 'T_int0' => 0, 'T_int2' => 2, 'T_null' => null, 'T_missing' => '__missing__', 'T_empty' => '', 'T_float' => 0.9, 'T_arr' => []] as $title => $accepted) {
            $files[\sprintf('src/Controller/%sController.php', $title)] = ProjectFixtures::controller(\sprintf('%sController', $title), [ProjectFixtures::finding(['type' => 'sql_injection', 'severity' => 'high', 'title' => $title, 'confidence' => 0.9, 'line_start' => 7])]);
            $verdicts = $verdicts->withReviewerVerdict($title, '__missing__' === $accepted ? ['reviewer_notes' => 'notes only'] : ['accepted' => $accepted, 'reviewer_notes' => 'x']);
        }

        $jsonCollection = ['structured_collection' => false, 'reviewer_structured_collection' => false, 'max_iterations' => 1];
        $scenario = Scenario::bundle('run/reviewer-accepted-spellings')->withProjectFiles($files)->withPlatform($verdicts)->withConfig(['audit' => $jsonCollection])->running(Step::audit(self::JSON));
        $sloppy = Scenario::bundle('run/sloppy-findings-json')->withProjectFiles(self::sloppyFindings())->withConfig(['audit' => $jsonCollection])->running(Step::audit(self::JSON));

        return [
            $scenario,
            $scenario->renamed('run/reviewer-accepted-spellings-batch')->withConfig(['audit' => [...$jsonCollection, 'reviewer_batch_size' => 20]]),
            $scenario->renamed('run/reviewer-accepted-spellings-fail-on-incomplete')->withoutSteps()->running(Step::audit([...self::JSON, '--fail-on-incomplete' => true])),
            $sloppy,
            $sloppy->renamed('run/sloppy-findings-structured')->withConfig(['audit' => ['max_iterations' => 1]]),
            $sloppy->renamed('run/sloppy-findings-fail-on-incomplete')->withConfig(['audit' => ['max_iterations' => 1]])->withoutSteps()->running(Step::audit([...self::JSON, '--fail-on-incomplete' => true])),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function extensions(): array
    {
        $scenario = self::base('run/custom-client-and-stage')
            ->collecting('custom-stage.json')
            ->withServices(static function (ContainerBuilder $containerBuilder): void {
                $containerBuilder->register(CustomLlmClient::class)->setPublic(true);
                $containerBuilder->setAlias('security_auditor.attacker_client', CustomLlmClient::class)->setPublic(true);
                $containerBuilder->setAlias('security_auditor.reviewer_client', CustomLlmClient::class)->setPublic(true);
                $containerBuilder->register(CountingStage::class)->addTag('symfony_security_auditor.pipeline_stage', ['priority' => -100])->setPublic(true);
            });

        return [
            $scenario,
            $scenario->renamed('run/custom-client-and-stage-json')->withConfig(['audit' => ['structured_collection' => false, 'reviewer_structured_collection' => false]]),
        ];
    }

    private static function base(string $name): Scenario
    {
        return Scenario::bundle($name)->withProjectFiles(ProjectFixtures::base())->running(Step::audit(self::JSON));
    }

    /**
     * @param list<array<string, bool|float|int|string>> $findings
     */
    private static function single(string $name, string $controller, array $findings): Scenario
    {
        return Scenario::bundle($name)
            ->withProjectFiles([\sprintf('src/Controller/%s.php', $controller) => ProjectFixtures::controller($controller, array_map(ProjectFixtures::finding(...), $findings))])
            ->running(Step::audit(self::JSON));
    }

    private static function escalation(): Scenario
    {
        return Scenario::bundle('run/escalation')
            ->withProjectFiles([
                'src/Controller/AdminController.php' => ProjectFixtures::controller('AdminController', [ProjectFixtures::finding(['type' => 'broken_access_control', 'severity' => 'critical', 'title' => 'Both models', 'confidence' => 0.95, 'line_start' => 7])]),
                'src/Controller/BController.php' => ProjectFixtures::controller('BController', [
                    ProjectFixtures::finding(['only_model' => 'gpt-4o-mini', 'type' => 'sql_injection', 'severity' => 'high', 'title' => 'Cheap only on hot file', 'confidence' => 0.9, 'line_start' => 7]),
                    ProjectFixtures::finding(['only_model' => 'gpt-4o', 'type' => 'ssrf', 'severity' => 'high', 'title' => 'Deep only', 'confidence' => 0.9, 'line_start' => 7]),
                ]),
                'src/Controller/CController.php' => ProjectFixtures::controller('CController', [ProjectFixtures::finding(['only_model' => 'gpt-4o-mini', 'type' => 'missing_csrf_protection', 'severity' => 'low', 'title' => 'cold', 'confidence' => 0.9])]),
                'src/Service/Cold.php' => \sprintf("<?php\nnamespace App\\Service;\n// %s\nclass Cold {}\n", ProjectFixtures::finding(['only_model' => 'gpt-4o-mini', 'type' => 'weak_cryptography', 'severity' => 'medium', 'title' => 'Cheap finding on cold file', 'confidence' => 0.8, 'line_start' => 3])),
            ])
            ->withConfig(['model' => 'gpt-4o', 'audit' => ['escalation' => ['enabled' => true, 'cheap_model' => 'gpt-4o-mini']]])
            ->running(Step::audit(self::JSON));
    }

    private static function pathSpellings(string $name): Scenario
    {
        $spellings = [
            ['./src/Controller/AdminController.php', 'broken_access_control', 'critical', 'dot-slash'],
            ['src/Controller/AdminController.php', 'sql_injection', 'high', 'plain'],
            ['src\Controller\AdminController.php', 'ssrf', 'high', 'backslash'],
            ['/src/Controller/AdminController.php', 'xxe', 'high', 'leading slash'],
            ['AdminController.php', 'open_redirect', 'high', 'basename only'],
            ['SRC/Controller/AdminController.php', 'path_traversal', 'high', 'case'],
            ['nonexistent/Foo.php', 'xpath_injection', 'high', 'unknown file'],
        ];

        return Scenario::bundle($name)
            ->withProjectFiles(['src/Controller/AdminController.php' => ProjectFixtures::controller('AdminController', array_map(
                static fn (array $spelling): string => ProjectFixtures::finding(['file_path' => $spelling[0], 'type' => $spelling[1], 'severity' => $spelling[2], 'title' => $spelling[3], 'confidence' => 0.95, 'line_start' => 7]),
                $spellings,
            ))])
            ->running(Step::audit(self::JSON));
    }

    /**
     * @return array<string, string>
     */
    private static function sloppyFindings(): array
    {
        $controllers = [
            'AController' => [['line_start' => '42-50', 'type' => 'sql_injection', 'title' => 'range string', 'confidence' => 0.9], ['line_start' => 7, 'type' => 'ssrf', 'title' => 'ok sibling', 'confidence' => 0.9]],
            'BController' => [['type' => 'not_a_type', 'title' => 'bad type', 'confidence' => 0.9, 'line_start' => 7]],
            'CController' => [['severity' => 'urgent', 'type' => 'xxe', 'title' => 'bad sev', 'confidence' => 0.9, 'line_start' => 7]],
            'DController' => [['confidence' => 'high', 'type' => 'xxe', 'title' => 'text conf', 'line_start' => 7]],
            'EController' => [['title' => '', 'type' => 'xxe', 'confidence' => 0.9, 'line_start' => 7]],
            'FController' => [['confidence' => 85, 'type' => 'xxe', 'title' => 'percent conf', 'line_start' => 7]],
            'GController' => [['line_end' => 3, 'line_start' => 9, 'type' => 'xxe', 'title' => 'inverted lines']],
        ];

        $files = [];
        foreach ($controllers as $controller => $findings) {
            $files[\sprintf('src/Controller/%s.php', $controller)] = ProjectFixtures::controller($controller, array_map(ProjectFixtures::finding(...), $findings));
        }

        return $files;
    }

    /**
     * @return list<SetupActionInterface>
     */
    private static function scanLayout(): array
    {
        $files = [
            'src/Big.php' => \sprintf("<?php\n// %s\n", str_repeat('x', 3000)),
            'src/Latin1.php' => "<?php\n// caf\xE9\n",
            'src/.hidden.php' => "<?php // hidden\n",
            'src/Empty.php' => '',
            'src/Crlf.php' => "<?php\r\nclass Crlf {}\r\n",
            'src/vendor/lib/Inner.php' => "<?php // nested vendor\n",
            'config/services.yaml' => "services:\n  _defaults: { autowire: true }\n",
            'config/routes.yml' => "x: { path: /x }\n",
            'config/bundles.php' => "<?php return [];\n",
            'config/legacy.xml' => "<a/>\n",
            'templates/sub/page.html.twig' => "{{ a }}\n",
            'templates/mail.txt.twig' => "{{ a }}\n",
            'public/index.php' => "<?php require '../vendor/autoload.php';\n",
            '.env' => "APP_SECRET=abc\n",
            '.env.local' => "DB=mysql://u:p@h/db\n",
            'src/Ignored/Foo.php' => "<?php // under var? no\n",
            'var/log/dev.log' => "log\n",
            'migrations/Version1.php' => "<?php // mig\n",
            'tests/FooTest.php' => "<?php // test\n",
            'assets/app.js' => "alert(1)\n",
            'src/data.json' => "{}\n",
            'src/Kernel.php' => "<?php class Kernel {}\n",
        ];

        $actions = [];
        foreach ($files as $path => $content) {
            $actions[] = new WriteFile(\sprintf('project/%s', $path), $content);
        }

        return [
            ...$actions,
            new Symlink('project/src/Controller/AdminController.php', 'project/src/Controller/LinkToAdmin.php'),
            new Symlink('project/src/Service', 'project/src/ServiceLink'),
        ];
    }

    /**
     * @return list<SetupActionInterface>
     */
    private static function changedAfterCommit(): array
    {
        return [
            new GitCommit(),
            new WriteFile('project/src/Controller/AdminController.php', ProjectFixtures::controller('AdminController', [\sprintf('%s changed', ProjectFixtures::finding(['type' => 'broken_access_control', 'severity' => 'critical', 'title' => 'Unprotected admin', 'confidence' => 0.95, 'line_start' => 7, 'line_end' => 8]))])),
            new WriteFile('project/src/Controller/NewController.php', ProjectFixtures::controller('NewController', [ProjectFixtures::finding(['type' => 'ssrf', 'severity' => 'high', 'title' => 'New file ssrf', 'confidence' => 0.9, 'line_start' => 7])])),
            new RemovePath('project/src/Service/Clean.php'),
        ];
    }
}
