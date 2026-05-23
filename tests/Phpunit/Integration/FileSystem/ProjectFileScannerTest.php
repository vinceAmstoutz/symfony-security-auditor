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

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Finder\SplFileInfo;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;

final class ProjectFileScannerTest extends TestCase
{
    private string $tmpDir;

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

    public function test_it_excludes_additional_dirs_from_config(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/legacy', 0o777, true);

        file_put_contents($this->tmpDir.'/src/App.php', '<?php class App {}');
        file_put_contents($this->tmpDir.'/legacy/Old.php', '<?php class Old {}');

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), additionalExcludedDirs: ['legacy']);

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('src/App.php', $files[0]->relativePath());
    }

    public function test_additional_excluded_dirs_do_not_replace_hard_defaults(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/vendor', 0o777, true);
        mkdir($this->tmpDir.'/legacy', 0o777, true);

        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/vendor/autoload.php', '<?php');
        file_put_contents($this->tmpDir.'/legacy/Old.php', '<?php');

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), additionalExcludedDirs: ['legacy']);

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('src/App.php', $files[0]->relativePath());
    }

    public function test_it_respects_gitignore_when_enabled(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/build', 0o777, true);
        file_put_contents($this->tmpDir.'/.gitignore', "build/\n");
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/build/Generated.php', '<?php');

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), respectGitignore: true);

        $files = $projectFileScanner->scan($this->tmpDir);

        self::assertCount(1, $files);
        self::assertSame('src/App.php', $files[0]->relativePath());
    }

    public function test_it_does_not_respect_gitignore_when_disabled(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/build', 0o777, true);
        file_put_contents($this->tmpDir.'/.gitignore', "build/\n");
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/build/Generated.php', '<?php');

        $projectFileScanner = new ProjectFileScanner(new NullLogger(), respectGitignore: false);

        $paths = array_map(
            static fn (ProjectFile $projectFile): string => $projectFile->relativePath(),
            $projectFileScanner->scan($this->tmpDir),
        );
        sort($paths);

        self::assertSame(['build/Generated.php', 'src/App.php'], $paths);
    }

    public function test_default_constructor_does_not_respect_gitignore(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/build', 0o777, true);
        file_put_contents($this->tmpDir.'/.gitignore', "build/\n");
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');
        file_put_contents($this->tmpDir.'/build/Generated.php', '<?php');

        $projectFileScanner = new ProjectFileScanner(new NullLogger());

        $paths = array_map(
            static fn (ProjectFile $projectFile): string => $projectFile->relativePath(),
            $projectFileScanner->scan($this->tmpDir),
        );
        sort($paths);

        self::assertSame(['build/Generated.php', 'src/App.php'], $paths);
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

    public function test_it_scrubs_secrets_from_file_content_when_scrubber_is_injected(): void
    {
        // Synthesize the credential-shaped value at runtime so the repository file
        // does not contain a string matching GitHub's secret scanner.
        $stripeShape = 'sk_live'.'_4eC39HqLyjWDarjtT1zdp7dc';

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
        $stripeShape = 'sk_live'.'_4eC39HqLyjWDarjtT1zdp7dc';
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

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/scanner_int_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
        $this->projectFileScanner = new ProjectFileScanner(new NullLogger());
    }

    protected function tearDown(): void
    {
        $this->rmdirRecursive($this->tmpDir);
    }

    private function rmdirRecursive(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (scandir($dir) as $item) {
            if ('.' === $item) {
                continue;
            }

            if ('..' === $item) {
                continue;
            }

            $path = $dir.'/'.$item;
            is_dir($path) ? $this->rmdirRecursive($path) : unlink($path);
        }

        rmdir($dir);
    }
}
