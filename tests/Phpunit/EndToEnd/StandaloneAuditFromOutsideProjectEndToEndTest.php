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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

/**
 * Runs the real `bin/symfony-security-auditor` entry script in a process of
 * its own, from a folder that is not the audited project, against a Symfony
 * project laid out like `symfony/demo` — the way a person types
 * `symfony-security-auditor audit <project> --path src/Command` — so the
 * working directory, the project argument and the `--path` option are
 * resolved by the shipped application and not by a hand-built command.
 * `--show-scanned` and `--dry-run` make no LLM call.
 */
final class StandaloneAuditFromOutsideProjectEndToEndTest extends TestCase
{
    private const array COMMAND_FILES = [
        'src/Command/AddUserCommand.php',
        'src/Command/DeleteUserCommand.php',
        'src/Command/ListUsersCommand.php',
    ];

    private const array OTHER_FILES = [
        'public/index.php',
        'src/Controller/BlogController.php',
        'src/Entity/User.php',
        'src/Kernel.php',
        'config/packages/security.yaml',
        'templates/base.html.twig',
    ];

    private const array MONOREPO_FILES = [
        'apps/api/config/services.yaml',
        'apps/api/src/ApiController.php',
        'apps/web/src/WebController.php',
    ];

    private Filesystem $filesystem;

    private string $base;

    private string $project;

    private string $elsewhere;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->base = sys_get_temp_dir().'/ssa-outside-'.bin2hex(random_bytes(4));
        $this->project = $this->base.'/project';
        $this->elsewhere = $this->base.'/elsewhere';

        $this->filesystem->mkdir($this->elsewhere);
        $this->filesystem->dumpFile(
            $this->base.'/config/symfony-security-auditor/config.yaml',
            "platform:\n  generic:\n    default:\n      base_url: 'http://localhost'\nmodel: 'gpt-4'\n",
        );
        $this->createSymfonyProject();
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->base);
    }

    #[DataProvider('waysToNameTheProject')]
    #[MaximumDuration(4000)]
    public function test_a_relative_path_scopes_the_scan_to_that_directory_whichever_way_the_project_is_named(string $workingFolder, string $projectArgument): void
    {
        $process = $this->audit(
            [$this->projectNamedAs($projectArgument), '--path', 'src/Command', '--show-scanned'],
            'base' === $workingFolder ? $this->base : $this->elsewhere,
        );

        self::assertSame(0, $process->getExitCode());
        $this->assertListsExactly(self::COMMAND_FILES, $this->displayOf($process));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function waysToNameTheProject(): iterable
    {
        yield 'an absolute path, from an unrelated folder' => ['elsewhere', 'absolute'];
        yield 'a path relative to the folder above it' => ['base', 'project'];
        yield 'a path that climbs out of the working folder' => ['elsewhere', '../project'];
    }

    #[MaximumDuration(4000)]
    public function test_an_absolute_path_inside_the_project_scopes_the_scan_to_that_directory(): void
    {
        $process = $this->audit([$this->project, '--path', $this->project.'/src/Command', '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        $this->assertListsExactly(self::COMMAND_FILES, $this->displayOf($process));
    }

    /**
     * @param list<string> $pathArguments
     * @param list<string> $expectedFiles
     */
    #[DataProvider('spellingsOfAPath')]
    #[MaximumDuration(4000)]
    public function test_every_spelling_of_a_path_scopes_the_scan_the_same_way(array $pathArguments, array $expectedFiles): void
    {
        $process = $this->audit([$this->project, ...$pathArguments, '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        $this->assertListsExactly($expectedFiles, $this->displayOf($process));
    }

    /**
     * @return iterable<string, array{list<string>, list<string>}>
     */
    public static function spellingsOfAPath(): iterable
    {
        yield 'with a trailing slash' => [['--path', 'src/Command/'], self::COMMAND_FILES];
        yield 'with the short option' => [['-p', 'src/Command'], self::COMMAND_FILES];
        yield 'with a leading dot segment' => [['--path', './src/Command'], self::COMMAND_FILES];
        yield 'with backslashes' => [['--path', 'src\\Command'], self::COMMAND_FILES];
        yield 'with several paths' => [['--path', 'src/Command', '--path', 'src/Entity'], [...self::COMMAND_FILES, 'src/Entity/User.php']];
        yield 'with a single file' => [['--path', 'src/Command/AddUserCommand.php'], ['src/Command/AddUserCommand.php']];
    }

    #[MaximumDuration(4000)]
    public function test_a_path_the_configured_scan_does_not_reach_is_scanned_itself(): void
    {
        $process = $this->audit([$this->project, '--path', 'apps/api', '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        $this->assertListsExactly(['apps/api/config/services.yaml', 'apps/api/src/ApiController.php'], $this->displayOf($process));
    }

    #[MaximumDuration(4000)]
    public function test_overlapping_paths_list_each_file_once(): void
    {
        $process = $this->audit([$this->project, '--path', 'apps/api', '--path', 'apps/api/src', '--path', 'apps/api', '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        $this->assertListsExactly(['apps/api/config/services.yaml', 'apps/api/src/ApiController.php'], $this->displayOf($process));
    }

    #[MaximumDuration(4000)]
    public function test_a_path_that_is_the_project_root_keeps_the_configured_scope(): void
    {
        $process = $this->audit([$this->project, '--path', $this->project, '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        $this->assertListsExactly([...self::COMMAND_FILES, ...self::OTHER_FILES], $this->displayOf($process));
    }

    #[MaximumDuration(4000)]
    public function test_a_path_outside_an_included_paths_that_the_user_config_narrowed_is_scanned_itself(): void
    {
        $this->filesystem->dumpFile(
            $this->base.'/config/symfony-security-auditor/config.yaml',
            "platform:\n  generic:\n    default:\n      base_url: 'http://localhost'\nmodel: 'gpt-4'\nscan:\n  included_paths:\n    - src/Controller\n",
        );

        $process = $this->audit([$this->project, '--show-scanned'], $this->elsewhere);
        $overridden = $this->audit([$this->project, '--path', 'src/Command', '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        self::assertSame(0, $overridden->getExitCode());
        $this->assertListsExactly(['src/Controller/BlogController.php'], $this->displayOf($process));
        $this->assertListsExactly(self::COMMAND_FILES, $this->displayOf($overridden));
    }

    #[MaximumDuration(4000)]
    public function test_a_path_wider_than_the_included_paths_of_the_user_config_audits_only_the_configured_part(): void
    {
        $this->filesystem->dumpFile(
            $this->base.'/config/symfony-security-auditor/config.yaml',
            "platform:\n  generic:\n    default:\n      base_url: 'http://localhost'\nmodel: 'gpt-4'\nscan:\n  included_paths:\n    - src/Controller\n",
        );

        $process = $this->audit([$this->project, '--path', 'src', '--show-scanned'], $this->elsewhere);
        $widerPathAndOneOutside = $this->audit([$this->project, '--path', 'src', '--path', 'apps/api', '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        self::assertSame(0, $widerPathAndOneOutside->getExitCode());
        $this->assertListsExactly(['src/Controller/BlogController.php'], $this->displayOf($process));
        $this->assertListsExactly(['src/Controller/BlogController.php'], $this->displayOf($widerPathAndOneOutside));
    }

    #[MaximumDuration(4000)]
    public function test_a_path_outside_a_project_config_which_wins_over_the_user_config_is_scanned_itself(): void
    {
        $this->filesystem->dumpFile(
            $this->base.'/config/symfony-security-auditor/config.yaml',
            "platform:\n  generic:\n    default:\n      base_url: 'http://localhost'\nmodel: 'gpt-4'\nscan:\n  included_paths:\n    - src/Controller\n",
        );

        $process = $this->audit([$this->project, '--show-scanned'], $this->elsewhere);
        $this->filesystem->dumpFile($this->project.'/.symfony-security-auditor.yaml', "scan:\n  included_paths:\n    - src/Entity\n");
        $projectConfigOverUser = $this->audit([$this->project, '--show-scanned'], $this->elsewhere);
        $flagOverBoth = $this->audit([$this->project, '--path', 'src/Command', '--show-scanned'], $this->elsewhere);

        $this->assertListsExactly(['src/Controller/BlogController.php'], $this->displayOf($process));
        $this->assertListsExactly(['src/Entity/User.php'], $this->displayOf($projectConfigOverUser));
        $this->assertListsExactly(self::COMMAND_FILES, $this->displayOf($flagOverBoth));
    }

    #[MaximumDuration(4000)]
    public function test_the_config_of_the_working_directory_does_not_apply_to_another_project(): void
    {
        $this->filesystem->dumpFile($this->elsewhere.'/.symfony-security-auditor.yaml', "scan:\n  included_paths:\n    - src/Entity\n");

        $process = $this->audit([$this->project, '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        $this->assertListsExactly([...self::COMMAND_FILES, ...self::OTHER_FILES], $this->displayOf($process));
    }

    #[MaximumDuration(4000)]
    public function test_the_config_of_the_project_applies_when_it_is_the_working_directory(): void
    {
        $this->filesystem->dumpFile($this->project.'/.symfony-security-auditor.yaml', "scan:\n  included_paths:\n    - src/Entity\n");

        $process = $this->audit(['--show-scanned'], $this->project);

        self::assertSame(0, $process->getExitCode());
        $this->assertListsExactly(['src/Entity/User.php'], $this->displayOf($process));
    }

    #[MaximumDuration(4000)]
    public function test_the_config_of_the_project_applies_when_it_is_named_relative_to_the_working_directory(): void
    {
        $this->filesystem->dumpFile($this->project.'/.symfony-security-auditor.yaml', "scan:\n  included_paths:\n    - src/Entity\n");

        $process = $this->audit(['project', '--show-scanned'], $this->base);

        self::assertSame(0, $process->getExitCode());
        $this->assertListsExactly(['src/Entity/User.php'], $this->displayOf($process));
    }

    #[MaximumDuration(4000)]
    public function test_without_a_path_the_whole_project_is_in_scope(): void
    {
        $process = $this->audit([$this->project, '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        $this->assertListsExactly([...self::COMMAND_FILES, ...self::OTHER_FILES], $this->displayOf($process));
    }

    #[MaximumDuration(4000)]
    public function test_a_dry_run_scoped_to_a_directory_estimates_less_than_the_whole_project(): void
    {
        $process = $this->audit([$this->project, '--dry-run'], $this->elsewhere);
        $scoped = $this->audit([$this->project, '--path', 'src/Command', '--dry-run'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        self::assertSame(0, $scoped->getExitCode());
        self::assertGreaterThan(0, $this->estimatedInputTokens($scoped));
        self::assertLessThan($this->estimatedInputTokens($process), $this->estimatedInputTokens($scoped));
    }

    #[MaximumDuration(4000)]
    public function test_naming_a_directory_inside_the_project_as_the_project_is_refused_before_anything_is_scanned(): void
    {
        $process = $this->audit(['src/Command', '--show-scanned'], $this->elsewhere);

        $output = $this->withoutWhitespace($this->displayOf($process));
        self::assertSame(1, $process->getExitCode());
        self::assertStringContainsString($this->withoutWhitespace(\sprintf('Project path "%s/src/Command" is not a valid directory', $this->elsewhere)), $output);
        self::assertStringNotContainsString('Nofilesmatched', $output);
    }

    #[MaximumDuration(4000)]
    public function test_an_absolute_path_outside_the_project_is_refused_naming_both(): void
    {
        $process = $this->audit([$this->project, '--path', $this->base.'/elsewhere', '--show-scanned'], $this->elsewhere);

        $output = $this->withoutWhitespace($this->displayOf($process));
        self::assertSame(1, $process->getExitCode());
        self::assertStringContainsString($this->withoutWhitespace(\sprintf('The --path "%s/elsewhere" lies outside the project "%s"', $this->base, $this->project)), $output);
        self::assertStringContainsString('relativetotheprojectroot', $output);
    }

    #[MaximumDuration(4000)]
    public function test_a_path_that_lists_nothing_names_the_project_and_the_path_it_looked_for(): void
    {
        $process = $this->audit([$this->project, '--path', 'src/Missing', '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        self::assertStringContainsString(
            $this->withoutWhitespace(\sprintf('No files matched under "%s" for --path src/Missing.', $this->project)),
            $this->withoutWhitespace($this->displayOf($process)),
        );
        self::assertStringNotContainsString('file(s)inscope', $this->withoutWhitespace($this->displayOf($process)));
    }

    #[MaximumDuration(4000)]
    public function test_running_from_outside_without_naming_the_project_says_which_folder_was_scanned(): void
    {
        $process = $this->audit(['--path', 'src/Command', '--show-scanned'], $this->elsewhere);

        self::assertSame(0, $process->getExitCode());
        self::assertStringContainsString(
            $this->withoutWhitespace(\sprintf('No files matched under "%s" for --path src/Command.', $this->elsewhere)),
            $this->withoutWhitespace($this->displayOf($process)),
        );
    }

    /**
     * @param list<string> $arguments
     */
    private function audit(array $arguments, string $workingDirectory): Process
    {
        $process = new Process(
            [\PHP_BINARY, \dirname(__DIR__, 3).'/bin/symfony-security-auditor', 'audit', '--no-ansi', ...$arguments],
            $workingDirectory,
            [
                'HOME' => $this->base,
                'PWD' => $workingDirectory,
                'XDG_CONFIG_HOME' => $this->base.'/config',
                'XDG_CACHE_HOME' => $this->base.'/cache',
                'XDG_DATA_HOME' => $this->base.'/data',
                'SSA_NO_UPDATE_CHECK' => '1',
                'GITHUB_ACTIONS' => false,
                'COLUMNS' => '200',
            ],
        );
        $process->setTimeout(120);
        $process->run();

        return $process;
    }

    private function projectNamedAs(string $projectArgument): string
    {
        return 'absolute' === $projectArgument ? $this->project : $projectArgument;
    }

    /**
     * @param list<string> $expectedFiles
     */
    private function assertListsExactly(array $expectedFiles, string $output): void
    {
        foreach ($expectedFiles as $expectedFile) {
            self::assertStringContainsString($expectedFile, $output);
        }

        foreach (array_diff([...self::COMMAND_FILES, ...self::OTHER_FILES, ...self::MONOREPO_FILES], $expectedFiles) as $excludedFile) {
            self::assertStringNotContainsString($excludedFile, $output);
        }

        self::assertStringContainsString(\sprintf('%d file(s) in scope.', \count($expectedFiles)), $output);
    }

    private function displayOf(Process $process): string
    {
        return $process->getOutput().$process->getErrorOutput();
    }

    private function withoutWhitespace(string $text): string
    {
        return preg_replace('/\s+/', '', $text) ?? $text;
    }

    private function estimatedInputTokens(Process $process): int
    {
        self::assertSame(1, preg_match('/Tokens:\s+([\d,]+) in/', $this->displayOf($process), $matches));

        return (int) str_replace(',', '', $matches[1]);
    }

    private function createSymfonyProject(): void
    {
        $files = [
            'composer.json' => '{"type":"project","require":{"php":">=8.3","symfony/framework-bundle":"^7.4"}}',
            'public/index.php' => "<?php\nrequire dirname(__DIR__).'/vendor/autoload_runtime.php';\n",
            'config/packages/security.yaml' => "security:\n  firewalls:\n    main:\n      pattern: ^/\n",
            'templates/base.html.twig' => "<!DOCTYPE html>\n<title>{% block title %}Demo{% endblock %}</title>\n",
            'src/Kernel.php' => "<?php\nnamespace App;\nuse Symfony\\Bundle\\FrameworkBundle\\Kernel\\MicroKernelTrait;\nuse Symfony\\Component\\HttpKernel\\Kernel as BaseKernel;\nclass Kernel extends BaseKernel { use MicroKernelTrait; }\n",
            'src/Controller/BlogController.php' => "<?php\nnamespace App\\Controller;\nuse Symfony\\Component\\HttpFoundation\\Response;\nuse Symfony\\Component\\Routing\\Attribute\\Route;\nclass BlogController\n{\n    #[Route('/blog', name: 'blog_index')]\n    public function index(): Response { return new Response('blog'); }\n}\n",
            'src/Entity/User.php' => "<?php\nnamespace App\\Entity;\nclass User { private ?int \$id = null; private string \$username = ''; }\n",
            'apps/api/config/services.yaml' => "services:\n  _defaults: { autowire: true }\n",
            'apps/api/src/ApiController.php' => "<?php\nnamespace Api;\nclass ApiController {}\n",
            'apps/web/src/WebController.php' => "<?php\nnamespace Web;\nclass WebController {}\n",
        ];

        foreach (['AddUser', 'DeleteUser', 'ListUsers'] as $command) {
            $files[\sprintf('src/Command/%sCommand.php', $command)] = \sprintf("<?php\nnamespace App\\Command;\nuse Symfony\\Component\\Console\\Attribute\\AsCommand;\n#[AsCommand(name: 'app:%s')]\nclass %sCommand { public function __invoke(): int { return 0; } }\n", strtolower($command), $command);
        }

        foreach ($files as $path => $content) {
            $this->filesystem->dumpFile($this->project.'/'.$path, $content);
        }
    }
}
