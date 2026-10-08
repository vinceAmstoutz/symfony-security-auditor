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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\FileSystem;

use Closure;
use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\SplFileInfo;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class ProjectFileScannerTest extends TestCase
{
    // Split via constant so neither CS Fixer's `no_useless_concat_operator`
    // nor GitHub's secret scanner sees a contiguous credential-shaped string.
    private const string STRIPE_LIVE_PREFIX = 'sk_live';

    private const int UNPRIVILEGED_USER_ID = 65534;

    private string $tmpDir;

    private Filesystem $filesystem;

    private ProjectFileScanner $projectFileScanner;

    public function test_it_scans_php_files_in_real_directory(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Controller/UserController.php', '<?php class UserController {}');

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('src/Controller/UserController.php', $files[0]->relativePath());
        self::assertSame('controller', $files[0]->type());
    }

    public function test_gitignored_files_are_scanned_by_default(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/.gitignore', "Ignored.php\n");
        file_put_contents($this->tmpDir.'/src/Ignored.php', '<?php class Ignored {}');
        file_put_contents($this->tmpDir.'/src/Kept.php', '<?php class Kept {}');

        $files = (new ProjectFileScanner(new NullLogger(), ['src']))->scan($this->tmpDir);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);

        self::assertContains('src/Ignored.php', $paths);
        self::assertContains('src/Kept.php', $paths);
    }

    public function test_it_scans_multiple_file_types(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/templates', 0o777, true);
        mkdir($this->tmpDir.'/config', 0o777, true);

        file_put_contents($this->tmpDir.'/src/Service.php', '<?php class Service {}');
        file_put_contents($this->tmpDir.'/templates/base.html.twig', '{{ user.name }}');
        file_put_contents($this->tmpDir.'/config/security.yaml', 'security: {}');

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertCount(3, $files);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);
        sort($paths);
        self::assertContains('config/security.yaml', $paths);
        self::assertContains('src/Service.php', $paths);
        self::assertContains('templates/base.html.twig', $paths);
    }

    public function test_it_excludes_vendor_directory(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/vendor', 0o777, true);

        file_put_contents($this->tmpDir.'/src/App.php', '<?php class App {}');
        file_put_contents($this->tmpDir.'/vendor/autoload.php', '<?php // vendor');

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('src/App.php', $files[0]->relativePath());
    }

    public function test_it_excludes_node_modules_directory(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/node_modules/pkg', 0o777, true);

        file_put_contents($this->tmpDir.'/src/App.php', '<?php class App {}');
        file_put_contents($this->tmpDir.'/node_modules/pkg/index.php', '<?php // npm');

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('src/App.php', $files[0]->relativePath());
    }

    public function test_it_scans_an_explicitly_included_dotenv_file(): void
    {
        file_put_contents($this->tmpDir.'/.env', "APP_ENV=prod\nAPP_SECRET=abcdef0123456789\n");

        $files = (new ProjectFileScanner(new NullLogger(), ['.env']))->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('.env', $files[0]->relativePath());
        self::assertSame('config', $files[0]->type());
    }

    public function test_default_included_paths_pick_up_committed_dotenv_files(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php class App {}');
        file_put_contents($this->tmpDir.'/.env', "APP_ENV=prod\n");
        file_put_contents($this->tmpDir.'/.env.dev', "APP_ENV=dev\n");

        $files = $this->projectFileScanner->scan($this->tmpDir);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);

        self::assertContains('.env', $paths);
        self::assertContains('.env.dev', $paths);
        self::assertContains('src/App.php', $paths);
    }

    public function test_default_included_paths_scan_src_config_templates_and_public_index(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/config', 0o777, true);
        mkdir($this->tmpDir.'/templates', 0o777, true);
        mkdir($this->tmpDir.'/public', 0o777, true);

        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/config/security.yaml', 'security: {}');
        file_put_contents($this->tmpDir.'/templates/base.html.twig', '{{ user.name }}');
        file_put_contents($this->tmpDir.'/public/index.php', '<?php // front controller');

        $paths = array_map(
            static fn (ProjectFile $projectFile): string => $projectFile->relativePath(),
            $this->projectFileScanner->scan($this->tmpDir),
        );
        sort($paths);

        self::assertSame(
            ['config/security.yaml', 'public/index.php', 'src/App.php', 'templates/base.html.twig'],
            $paths,
        );
    }

    public function test_it_skips_files_outside_default_included_paths(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/app', 0o777, true);

        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/app/Legacy.php', '<?php');
        file_put_contents($this->tmpDir.'/root-script.php', '<?php');

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('src/App.php', $files[0]->relativePath());
    }

    public function test_it_only_includes_public_index_when_other_public_files_present(): void
    {
        mkdir($this->tmpDir.'/public', 0o777, true);
        file_put_contents($this->tmpDir.'/public/index.php', '<?php // front controller');
        file_put_contents($this->tmpDir.'/public/dev.php', '<?php // dev script');

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('public/index.php', $files[0]->relativePath());
    }

    public function test_it_uses_custom_included_paths_when_provided(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/app', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Should.php', '<?php // ignored');
        file_put_contents($this->tmpDir.'/app/MyClass.php', '<?php');

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), includedPaths: ['app']);

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('app/MyClass.php', $files[0]->relativePath());
    }

    public function test_it_accumulates_every_explicit_file_across_included_paths(): void
    {
        mkdir($this->tmpDir.'/public', 0o777, true);
        mkdir($this->tmpDir.'/bin', 0o777, true);
        file_put_contents($this->tmpDir.'/public/index.php', '<?php // front controller');
        file_put_contents($this->tmpDir.'/bin/console.php', '<?php // console');

        $projectFileScanner = new ProjectFileScanner(
            new NullLogger(),
            includedPaths: ['public/index.php', 'bin/console.php'],
        );

        $paths = array_map(
            static fn (ProjectFile $projectFile): string => $projectFile->relativePath(),
            $projectFileScanner->scan($this->tmpDir),
        );
        sort($paths);

        self::assertSame(['bin/console.php', 'public/index.php'], $paths);
    }

    public function test_it_returns_files_in_relative_path_order_whatever_the_filesystem_lists_first(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        mkdir($this->tmpDir.'/config', 0o777, true);
        mkdir($this->tmpDir.'/public', 0o777, true);
        foreach (['src/b.php', 'src/Controller/a.php', 'src/a.php', 'src/c.php', 'config/z.yaml', 'config/a.yaml', 'public/index.php'] as $path) {
            file_put_contents(\sprintf('%s/%s', $this->tmpDir, $path), '<?php');
        }

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), includedPaths: ['src', 'public/index.php', 'config']);

        self::assertSame(
            ['config/a.yaml', 'config/z.yaml', 'public/index.php', 'src/Controller/a.php', 'src/a.php', 'src/b.php', 'src/c.php'],
            array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $projectFileScanner->scan($this->tmpDir)),
        );
    }

    public function test_it_logs_warning_and_returns_empty_when_no_included_paths_exist(): void
    {
        $warningLogs = [];
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warningLogs): void {
                $warningLogs[] = [$msg, $ctx];
            },
        );

        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');

        $projectFileScanner = new ProjectFileScanner($logger, includedPaths: ['nonexistent']);

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertSame([], $files);
        self::assertCount(1, $warningLogs);
        self::assertSame('No included paths exist in project', $warningLogs[0][0]);
        self::assertSame(['nonexistent'], $warningLogs[0][1]['included_paths']);

        $completeLogs = array_values(array_filter(
            $infoLogs,
            static fn (array $entry): bool => 'Scan complete' === $entry[0],
        ));
        self::assertEmpty($completeLogs);
    }

    public function test_it_does_not_match_sibling_directory_that_shares_a_prefix_with_included_path(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/srcfoo', 0o777, true);

        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/srcfoo/Sibling.php', '<?php');

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('src/App.php', $files[0]->relativePath());
    }

    public function test_it_returns_empty_for_directory_with_no_matching_files(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/notes.txt', 'just a note');

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertEmpty($files);
    }

    public function test_filter_by_type_returns_only_controllers(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        mkdir($this->tmpDir.'/src/Entity', 0o777, true);

        file_put_contents($this->tmpDir.'/src/Controller/UserController.php', '<?php');
        file_put_contents($this->tmpDir.'/src/Entity/User.php', '<?php');

        $files = $this->projectFileScanner->scan($this->tmpDir);
        $controllers = $this->projectFileScanner->filterByType($files, 'controller');

        self::assertCount(1, $controllers);
        self::assertSame('src/Controller/UserController.php', $controllers[0]->relativePath());
    }

    public function test_build_context_includes_file_path_and_content(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents(
            $this->tmpDir.'/src/Controller/UserController.php',
            '<?php class UserController { public function sensitiveAction() {} }',
        );

        $files = $this->projectFileScanner->scan($this->tmpDir);
        $context = $this->projectFileScanner->buildContext($files);

        self::assertStringContainsString('UserController.php', $context);
        self::assertStringContainsString('sensitiveAction', $context);
    }

    public function test_scanned_file_content_matches_actual_file(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        $content = '<?php echo "hello world";';
        file_put_contents($this->tmpDir.'/src/Hello.php', $content);

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame($content, $files[0]->content());
    }

    public function test_it_replaces_bytes_that_are_not_valid_utf8_in_file_content_with_the_replacement_character(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Legacy.php', "<?php\n// caf\xE9\n");

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame("<?php\n// caf\u{FFFD}\n", $files[0]->content());
    }

    public function test_it_replaces_bytes_that_are_not_valid_utf8_in_a_file_name_with_the_replacement_character(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        $absolutePath = $this->tmpDir."/src/Controller/Fo\xFFo.php";
        file_put_contents($absolutePath, '<?php class Foo {}');

        $files = $this->projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame("src/Controller/Fo\u{FFFD}o.php", $files[0]->relativePath());
        self::assertSame($absolutePath, $files[0]->absolutePath());
    }

    public function test_it_warns_once_that_the_content_of_a_file_was_not_valid_utf8(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Legacy.php', "<?php\n// caf\xE9\n");

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $message, array $context = []) use (&$warnings): void {
                $warnings[] = [$message, $context];
            },
        );

        (new ProjectFileScanner($logger))->scan($this->tmpDir);

        self::assertSame([['File content is not valid UTF-8, its invalid bytes were replaced', ['path' => 'src/Legacy.php']]], $warnings);
    }

    public function test_it_warns_once_that_a_file_name_was_not_valid_utf8_and_names_it_as_replaced(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir."/src/Fo\xFFo.php", '<?php class Foo {}');

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $message, array $context = []) use (&$warnings): void {
                $warnings[] = [$message, $context];
            },
        );

        (new ProjectFileScanner($logger))->scan($this->tmpDir);

        self::assertSame([['File name is not valid UTF-8, its invalid bytes were replaced', ['path' => "src/Fo\u{FFFD}o.php"]]], $warnings);
    }

    public function test_it_does_not_warn_about_encoding_for_valid_utf8_names_and_content(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Café.php', "<?php\n// café\n");

        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('warning');

        $files = (new ProjectFileScanner($logger))->scan($this->tmpDir);

        self::assertSame(['src/Café.php' => "<?php\n// café\n"], [$files[0]->relativePath() => $files[0]->content()]);
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_the_secret_scrubber_sees_the_bytes_of_a_file_as_they_are_on_disk(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Legacy.php', "<?php\n// geheim\xE4 caf\xE9\n");

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), secretScrubber: new RegexSecretScrubber(["/geheim\xE4/"]));
        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertSame("<?php\n// ***REDACTED:custom_0*** caf\u{FFFD}\n", $files[0]->content());
    }

    public function test_it_logs_scanning_start_and_completion_with_exact_context(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/A.php', '<?php');

        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $projectFileScanner = new ProjectFileScanner($logger);
        $projectFileScanner->scan($this->tmpDir);

        self::assertSame(['Scanning project', ['path' => $this->tmpDir]], $infoLogs[0]);
        self::assertSame(['Scan complete', ['files' => 1]], $infoLogs[1]);
    }

    public function test_it_respects_gitignore_when_enabled(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/derived', 0o777, true);
        file_put_contents($this->tmpDir.'/.gitignore', "derived/\n");
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/derived/Generated.php', '<?php');
        (new Process(['git', 'init', '--quiet', $this->tmpDir]))->mustRun();

        $projectFileScanner = new ProjectFileScanner(
            new NullLogger(),
            includedPaths: ['src', 'derived'],
            respectGitignore: true,
        );

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('src/App.php', $files[0]->relativePath());
    }

    public function test_it_does_not_respect_gitignore_when_disabled(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/derived', 0o777, true);
        file_put_contents($this->tmpDir.'/.gitignore', "derived/\n");
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/derived/Generated.php', '<?php');

        $projectFileScanner = new ProjectFileScanner(
            new NullLogger(),
            includedPaths: ['src', 'derived'],
            respectGitignore: false,
        );

        $paths = array_map(
            static fn (ProjectFile $projectFile): string => $projectFile->relativePath(),
            $projectFileScanner->scan($this->tmpDir),
        );
        sort($paths);

        self::assertSame(['derived/Generated.php', 'src/App.php'], $paths);
    }

    public function test_a_directory_inside_another_scanned_directory_is_not_read_twice(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Controller/HomeController.php', '<?php');
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        $reads = [];
        $reader = static function (SplFileInfo $splFile) use (&$reads): string {
            $reads[] = $splFile->getFilename();

            return $splFile->getContents();
        };

        $files = (new ProjectFileScanner(new NullLogger(), includedPaths: ['src', 'src/Controller'], fileReader: $reader))->scan($this->tmpDir);

        sort($reads);
        self::assertSame(['App.php', 'HomeController.php'], $reads);
        self::assertCount(2, $files);
    }

    public function test_a_directory_listed_twice_is_read_once(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        $reads = 0;
        $reader = static function (SplFileInfo $splFile) use (&$reads): string {
            ++$reads;

            return $splFile->getContents();
        };

        (new ProjectFileScanner(new NullLogger(), includedPaths: ['src', 'src/', './src'], fileReader: $reader))->scan($this->tmpDir);

        self::assertSame(1, $reads);
    }

    public function test_a_sibling_directory_sharing_a_name_prefix_is_not_taken_for_a_nested_one(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/src-extra', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/src-extra/Extra.php', '<?php');

        $paths = array_map(
            static fn (ProjectFile $projectFile): string => $projectFile->relativePath(),
            (new ProjectFileScanner(new NullLogger(), includedPaths: ['src', 'src-extra']))->scan($this->tmpDir),
        );

        self::assertSame(['src-extra/Extra.php', 'src/App.php'], $paths);
    }

    public function test_a_file_reached_by_two_scan_paths_is_the_first_one_read(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        $reads = 0;
        $reader = static function (SplFileInfo $splFile) use (&$reads): string {
            return \sprintf('<?php // read %d', ++$reads);
        };

        $files = (new ProjectFileScanner(new NullLogger(), includedPaths: ['src', 'src/App.php'], fileReader: $reader))->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertStringEndsWith('read 1', $files[0]->content());
    }

    public function test_default_constructor_does_not_respect_gitignore(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/derived', 0o777, true);
        file_put_contents($this->tmpDir.'/.gitignore', "derived/\n");
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/derived/Generated.php', '<?php');

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), includedPaths: ['src', 'derived']);

        $paths = array_map(
            static fn (ProjectFile $projectFile): string => $projectFile->relativePath(),
            $projectFileScanner->scan($this->tmpDir),
        );
        sort($paths);

        self::assertSame(['derived/Generated.php', 'src/App.php'], $paths);
    }

    public function test_it_skips_files_larger_than_configured_max_size(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Small.php', '<?php');
        file_put_contents($this->tmpDir.'/src/Big.php', '<?php /* '.str_repeat('x', 3 * 1024).' */');

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2);

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('src/Small.php', $files[0]->relativePath());
    }

    public function test_it_skips_explicit_file_path_when_larger_than_configured_max_size(): void
    {
        mkdir($this->tmpDir.'/public', 0o777, true);
        file_put_contents(
            $this->tmpDir.'/public/index.php',
            '<?php /* '.str_repeat('x', 3 * 1024).' */',
        );

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2);

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertSame([], $files);
    }

    public function test_it_keeps_explicit_file_at_exact_max_size_boundary(): void
    {
        mkdir($this->tmpDir.'/public', 0o777, true);
        // 2 KB exactly — `str_repeat('a', 2 * 1024)` is 2048 bytes on disk.
        file_put_contents($this->tmpDir.'/public/index.php', str_repeat('a', 2 * 1024));

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2);

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('public/index.php', $files[0]->relativePath());
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_it_scrubs_secrets_from_file_content_when_scrubber_is_injected(): void
    {
        $stripeShape = self::STRIPE_LIVE_PREFIX.'_4eC39HqLyjWDarjtT1zdp7dc';

        mkdir($this->tmpDir.'/config', 0o777, true);
        file_put_contents(
            $this->tmpDir.'/config/.env.dist',
            "APP_ENV=dev\nSTRIPE_SECRET_KEY=".$stripeShape."\n",
        );
        file_put_contents(
            $this->tmpDir.'/config/secrets.yaml',
            "stripe:\n    key: ".$stripeShape."\n",
        );

        // .env.dist is not in the scanner's tracked extensions, but secrets.yaml is.
        $projectFileScanner = new ProjectFileScanner(
            new NullLogger(),
            secretScrubber: new RegexSecretScrubber(),
        );

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertNotEmpty($files);
        foreach ($files as $file) {
            self::assertStringNotContainsString($stripeShape, $file->content());
        }
    }

    public function test_null_scrubber_leaves_file_content_unmodified(): void
    {
        $stripeShape = self::STRIPE_LIVE_PREFIX.'_4eC39HqLyjWDarjtT1zdp7dc';
        mkdir($this->tmpDir.'/config', 0o777, true);
        $original = "stripe:\n    key: ".$stripeShape."\n";
        file_put_contents($this->tmpDir.'/config/secrets.yaml', $original);

        $projectFileScanner = new ProjectFileScanner(
            new NullLogger(),
            secretScrubber: new NullSecretScrubber(),
        );

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame($original, $files[0]->content());
    }

    public function test_it_logs_warning_and_skips_files_whose_contents_cannot_be_read(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Readable.php', '<?php');
        file_put_contents($this->tmpDir.'/src/Unreadable.php', '<?php');

        /** @var list<array{string, array<string, string>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('info');

        $reader = static function (SplFileInfo $splFile): string {
            if (str_ends_with($splFile->getPathname(), 'Unreadable.php')) {
                throw new RuntimeException('disk read error');
            }

            return $splFile->getContents();
        };

        $projectFileScanner = new ProjectFileScanner($logger, fileReader: $reader);
        $files = $projectFileScanner->scan($this->tmpDir);

        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);
        self::assertSame(['src/Readable.php'], $paths);

        self::assertCount(1, $warnings);
        self::assertSame('Failed to read file', $warnings[0][0]);
        $context = $warnings[0][1];
        $path = $context['path'];
        $error = $context['error'];
        self::assertIsString($path);
        self::assertIsString($error);
        self::assertStringEndsWith('Unreadable.php', $path);
        self::assertSame('disk read error', $error);
    }

    public function test_it_skips_an_unreadable_directory_and_logs_it_instead_of_aborting_the_scan(): void
    {
        mkdir($this->tmpDir.'/src/Locked', 0o777, true);
        mkdir($this->tmpDir.'/src/Zeta', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Readable.php', '<?php class Readable {}');
        file_put_contents($this->tmpDir.'/src/Locked/Hidden.php', '<?php class Hidden {}');
        file_put_contents($this->tmpDir.'/src/Zeta/Later.php', '<?php class Later {}');
        $warningCollectingLogger = new WarningCollectingLogger();
        $projectFileScanner = new ProjectFileScanner($warningCollectingLogger, ['src']);
        $projectFileScanner->scan($this->tmpDir);
        chmod($this->tmpDir.'/src/Locked', 0o000);

        try {
            $files = $this->asUnprivilegedUser(fn (): array => $projectFileScanner->scan($this->tmpDir));
        } finally {
            chmod($this->tmpDir.'/src/Locked', 0o755);
        }

        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);
        self::assertSame(['src/Readable.php', 'src/Zeta/Later.php'], $paths);
        self::assertCount(1, $warningCollectingLogger->warnings);
        [$message, $context] = $warningCollectingLogger->warnings[0];
        self::assertSame('Skipped unreadable directory', $message);
        self::assertSame($this->tmpDir.'/src/Locked', $context['path']);
        self::assertIsString($context['error']);
        self::assertStringContainsString('Permission denied', $context['error']);
    }

    public function test_it_skips_a_symlinked_file_and_logs_a_warning(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Real.php', '<?php class Real {}');

        $outsideFile = sys_get_temp_dir().'/scanner_int_outside_'.uniqid('', true).'.php';
        file_put_contents($outsideFile, '<?php // outside the project root');
        symlink($outsideFile, $this->tmpDir.'/src/Linked.php');

        /** @var list<array{string, array<string, string>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('info');

        $projectFileScanner = new ProjectFileScanner($logger);

        try {
            $files = $projectFileScanner->scan($this->tmpDir);

            $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);
            self::assertSame(['src/Real.php'], $paths);

            self::assertCount(1, $warnings);
            self::assertSame('Skipped symlinked file', $warnings[0][0]);
            $path = $warnings[0][1]['path'];
            self::assertIsString($path);
            self::assertStringEndsWith('src/Linked.php', $path);
        } finally {
            unlink($outsideFile);
        }
    }

    public function test_it_skips_a_symlinked_included_directory_and_logs_a_warning(): void
    {
        mkdir($this->tmpDir.'/config', 0o777, true);
        file_put_contents($this->tmpDir.'/config/security.yaml', 'security: {}');

        $outsideDir = sys_get_temp_dir().'/scanner_int_outside_dir_'.uniqid('', true);
        mkdir($outsideDir, 0o777, true);
        file_put_contents($outsideDir.'/Secret.php', '<?php $secretApiKey = \'AKIAIOSFODNN7EXAMPLE\';');
        symlink($outsideDir, $this->tmpDir.'/src');

        /** @var list<array{string, array<string, string>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('info');

        $projectFileScanner = new ProjectFileScanner($logger);

        try {
            $files = $projectFileScanner->scan($this->tmpDir);

            $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);
            self::assertSame(['config/security.yaml'], $paths);

            self::assertCount(1, $warnings);
            self::assertSame('Skipped symlinked included path', $warnings[0][0]);
            $path = $warnings[0][1]['path'];
            self::assertIsString($path);
            self::assertStringEndsWith('/src', $path);
        } finally {
            $this->filesystem->remove($outsideDir);
        }
    }

    public function test_an_included_path_that_traverses_outside_the_project_root_is_skipped_and_logged(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Real.php', '<?php class Real {}');
        mkdir($this->tmpDir.'/config', 0o777, true);
        file_put_contents($this->tmpDir.'/config/security.yaml', 'security: {}');

        $outsideDir = sys_get_temp_dir().'/scanner_int_outside_dir_'.uniqid('', true);
        mkdir($outsideDir, 0o777, true);
        file_put_contents($outsideDir.'/Secret.php', '<?php $secretApiKey = \'AKIAIOSFODNN7EXAMPLE\';');

        /** @var list<array{string, array<string, string>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('info');

        $traversalPath = '../'.basename($outsideDir);
        $projectFileScanner = new ProjectFileScanner($logger, ['src', $traversalPath, 'config']);

        try {
            $files = $projectFileScanner->scan($this->tmpDir);

            $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);
            self::assertSame(['config/security.yaml', 'src/Real.php'], $paths);

            self::assertCount(1, $warnings);
            self::assertSame('Skipped included path outside the project root', $warnings[0][0]);
            $path = $warnings[0][1]['path'];
            self::assertIsString($path);
            self::assertStringEndsWith($traversalPath, $path);
        } finally {
            $this->filesystem->remove($outsideDir);
        }
    }

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/scanner_int_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
        $this->projectFileScanner = new ProjectFileScanner(new NullLogger());
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    public function test_an_included_path_reached_through_a_symlinked_directory_is_skipped_and_logged(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Real.php', '<?php class Real {}');

        $outsideDir = sys_get_temp_dir().'/scanner_int_outside_dir_'.uniqid('', true);
        mkdir($outsideDir, 0o777, true);
        file_put_contents($outsideDir.'/Secret.php', '<?php $secretApiKey = \'AKIAIOSFODNN7EXAMPLE\';');
        mkdir($outsideDir.'/deep', 0o777, true);
        symlink($outsideDir, $this->tmpDir.'/src/link');

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('info');

        $projectFileScanner = new ProjectFileScanner($logger, ['src/link/', 'src/link/deep/..', 'src/Real.php']);

        try {
            $files = $projectFileScanner->scan($this->tmpDir);

            $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);
            self::assertSame(['src/Real.php'], $paths);

            self::assertSame(['Skipped included path outside the project root', 'Skipped included path outside the project root'], array_column($warnings, 0));
        } finally {
            $this->filesystem->remove($outsideDir);
        }
    }

    public function test_an_explicit_file_reached_through_a_symlinked_directory_is_skipped(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);

        $outsideDir = sys_get_temp_dir().'/scanner_int_outside_dir_'.uniqid('', true);
        mkdir($outsideDir, 0o777, true);
        file_put_contents($outsideDir.'/credentials', 'aws_secret_access_key = AKIAIOSFODNN7EXAMPLE');
        symlink($outsideDir, $this->tmpDir.'/src/link');

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), ['src/link/credentials']);

        try {
            self::assertSame([], $projectFileScanner->scan($this->tmpDir));
        } finally {
            $this->filesystem->remove($outsideDir);
        }
    }

    public function test_it_scans_nothing_when_the_project_path_does_not_exist(): void
    {
        self::assertSame([], $this->projectFileScanner->scan($this->tmpDir.'/missing-'.uniqid('', true)));
    }

    /**
     * @param Closure(): list<ProjectFile> $action
     *
     * @return list<ProjectFile>
     */
    private function asUnprivilegedUser(Closure $action): array
    {
        if (0 !== posix_geteuid()) {
            return $action();
        }

        self::assertTrue(posix_seteuid(self::UNPRIVILEGED_USER_ID));

        try {
            return $action();
        } finally {
            posix_seteuid(0);
        }
    }
}
