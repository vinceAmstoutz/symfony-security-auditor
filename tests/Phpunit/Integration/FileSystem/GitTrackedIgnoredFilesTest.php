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

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\GitTrackedIgnoredFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class GitTrackedIgnoredFilesTest extends TestCase
{
    private string $tmpDir;

    private Filesystem $filesystem;

    public function test_it_lists_only_the_tracked_files_a_gitignore_pattern_matches(): void
    {
        $this->filesystem->mkdir($this->tmpDir.'/src/Generated');
        $this->filesystem->dumpFile($this->tmpDir.'/.gitignore', "src/Evil.php\nsrc/Untracked.php\nsrc/Generated/\n");
        $this->filesystem->dumpFile($this->tmpDir.'/src/Evil.php', '<?php');
        $this->filesystem->dumpFile($this->tmpDir.'/src/Untracked.php', '<?php');
        $this->filesystem->dumpFile($this->tmpDir.'/src/Generated/Cache.php', '<?php');
        $this->filesystem->dumpFile($this->tmpDir.'/src/Ok.php', '<?php');
        (new Process(['git', 'init', '--quiet', $this->tmpDir]))->mustRun();
        (new Process(['git', 'add', '--force', 'src/Evil.php', 'src/Generated/Cache.php', 'src/Ok.php'], $this->tmpDir))->mustRun();

        $paths = (new GitTrackedIgnoredFiles(new NullLogger()))->in($this->tmpDir);

        sort($paths);
        self::assertSame(['src/Evil.php', 'src/Generated/Cache.php'], $paths);
    }

    public function test_it_lists_nothing_for_a_repository_that_ignores_no_tracked_file(): void
    {
        $this->filesystem->dumpFile($this->tmpDir.'/src/Ok.php', '<?php');
        (new Process(['git', 'init', '--quiet', $this->tmpDir]))->mustRun();
        (new Process(['git', 'add', 'src/Ok.php'], $this->tmpDir))->mustRun();

        self::assertSame([], (new GitTrackedIgnoredFiles(new NullLogger()))->in($this->tmpDir));
    }

    public function test_it_names_the_files_relative_to_a_project_inside_a_larger_repository(): void
    {
        $this->filesystem->mkdir($this->tmpDir.'/apps/api/src');
        $this->filesystem->dumpFile($this->tmpDir.'/.gitignore', "Evil.php\n");
        $this->filesystem->dumpFile($this->tmpDir.'/apps/api/src/Evil.php', '<?php');
        $this->filesystem->dumpFile($this->tmpDir.'/Evil.php', '<?php');
        (new Process(['git', 'init', '--quiet', $this->tmpDir]))->mustRun();
        (new Process(['git', 'add', '--force', 'Evil.php', 'apps/api/src/Evil.php'], $this->tmpDir))->mustRun();

        self::assertSame(['src/Evil.php'], (new GitTrackedIgnoredFiles(new NullLogger()))->in($this->tmpDir.'/apps/api'));
    }

    public function test_it_does_not_run_the_filesystem_monitor_hook_the_audited_repository_configures(): void
    {
        $this->filesystem->dumpFile($this->tmpDir.'/src/Ok.php', '<?php');
        (new Process(['git', 'init', '--quiet', $this->tmpDir]))->mustRun();
        (new Process(['git', 'add', 'src/Ok.php'], $this->tmpDir))->mustRun();
        $marker = $this->tmpDir.'/hook-ran';
        $this->filesystem->dumpFile($this->tmpDir.'/hook.sh', \sprintf("#!/bin/sh\ntouch '%s'\n", $marker));
        $this->filesystem->chmod($this->tmpDir.'/hook.sh', 0o755);
        (new Process(['git', 'config', 'core.fsmonitor', $this->tmpDir.'/hook.sh'], $this->tmpDir))->mustRun();

        (new GitTrackedIgnoredFiles(new NullLogger()))->in($this->tmpDir);

        self::assertFileDoesNotExist($marker);
    }

    public function test_a_directory_that_is_not_a_git_repository_has_no_tracked_file_and_no_warning(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();

        self::assertSame([], (new GitTrackedIgnoredFiles($warningCollectingLogger))->in($this->tmpDir));
        self::assertSame([], $warningCollectingLogger->warnings);
    }

    public function test_a_git_failure_in_a_checkout_is_warned_about_and_lists_nothing(): void
    {
        $this->filesystem->mkdir($this->tmpDir.'/.git');
        $warningCollectingLogger = new WarningCollectingLogger();

        self::assertSame([], (new GitTrackedIgnoredFiles($warningCollectingLogger))->in($this->tmpDir));

        self::assertCount(1, $warningCollectingLogger->warnings);
        [$message, $context] = $warningCollectingLogger->warnings[0];
        self::assertSame('Could not list the files git tracks, a tracked file a .gitignore pattern matches is left out of the scan', $message);
        self::assertSame(['path', 'error'], array_keys($context));
        self::assertSame($this->tmpDir, $context['path']);
        self::assertNotSame('', $context['error']);
    }

    public function test_a_git_process_that_runs_too_long_in_a_checkout_is_warned_about_and_lists_nothing(): void
    {
        $this->filesystem->mkdir($this->tmpDir.'/.git');
        $warningCollectingLogger = new WarningCollectingLogger();

        self::assertSame([], (new GitTrackedIgnoredFiles($warningCollectingLogger, $this->stalledGit(...)))->in($this->tmpDir));

        self::assertCount(1, $warningCollectingLogger->warnings);
        $context = $warningCollectingLogger->warnings[0][1];
        self::assertSame($this->tmpDir, $context['path']);
        self::assertIsString($context['error']);
        self::assertStringContainsString('exceeded the timeout', $context['error']);
    }

    public function test_a_git_process_that_runs_too_long_outside_a_checkout_lists_nothing_without_a_warning(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();

        self::assertSame([], (new GitTrackedIgnoredFiles($warningCollectingLogger, $this->stalledGit(...)))->in($this->tmpDir));
        self::assertSame([], $warningCollectingLogger->warnings);
    }

    private function stalledGit(string $projectPath): Process
    {
        return (new Process([\PHP_BINARY, '-r', 'sleep(30);'], $projectPath))->setTimeout(0.2);
    }

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/git_tracked_ignored_'.bin2hex(random_bytes(6));
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }
}
