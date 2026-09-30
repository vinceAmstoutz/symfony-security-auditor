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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\SymlinkGuard;

final class SymlinkGuardTest extends TestCase
{
    private Filesystem $filesystem;

    private string $root;

    private string $outside;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->root = sys_get_temp_dir().'/symlink_guard_root_'.bin2hex(random_bytes(6));
        $this->outside = sys_get_temp_dir().'/symlink_guard_outside_'.bin2hex(random_bytes(6));
        $this->filesystem->mkdir([$this->root, $this->outside.'/reports']);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove([$this->root, $this->outside]);
    }

    public function test_a_plain_path_under_the_root_is_not_through_a_symlink(): void
    {
        $this->filesystem->mkdir($this->root.'/build/reports');

        self::assertFalse(SymlinkGuard::isThroughSymlink($this->root.'/build/reports/report.json', $this->root));
    }

    public function test_a_symlinked_file_is_through_a_symlink(): void
    {
        symlink($this->outside.'/target.json', $this->root.'/report.json');

        self::assertTrue(SymlinkGuard::isThroughSymlink($this->root.'/report.json', $this->root));
    }

    public function test_a_symlinked_directory_is_through_a_symlink(): void
    {
        symlink($this->outside, $this->root.'/build');

        self::assertTrue(SymlinkGuard::isThroughSymlink($this->root.'/build/report.json', $this->root));
    }

    public function test_a_slash_terminated_symlinked_directory_is_through_a_symlink(): void
    {
        $this->filesystem->symlink($this->outside.'/reports', $this->root.'/reports');

        self::assertTrue(SymlinkGuard::isThroughSymlink($this->root.'/reports/', $this->root));
    }

    public function test_a_slash_terminated_plain_directory_is_not_through_a_symlink(): void
    {
        $this->filesystem->mkdir($this->root.'/reports');

        self::assertFalse(SymlinkGuard::isThroughSymlink($this->root.'/reports/', $this->root));
    }

    public function test_a_symlinked_directory_between_the_root_and_the_file_is_through_a_symlink(): void
    {
        symlink($this->outside, $this->root.'/build');

        self::assertTrue(SymlinkGuard::isThroughSymlink($this->root.'/build/reports/report.json', $this->root));
    }

    public function test_a_relative_path_is_resolved_against_the_working_directory(): void
    {
        symlink($this->outside, $this->root.'/build');

        self::assertTrue($this->fromRoot(fn (): bool => SymlinkGuard::isThroughSymlink('build/reports/report.json', $this->root)));
        self::assertFalse($this->fromRoot(fn (): bool => SymlinkGuard::isThroughSymlink('build/reports/report.json', $this->outside)));
    }

    public function test_a_relative_root_is_resolved_against_the_working_directory(): void
    {
        $this->filesystem->mkdir($this->root.'/cache/plain');
        symlink($this->outside, $this->root.'/cache/link');

        self::assertTrue($this->fromRoot(static fn (): bool => SymlinkGuard::isThroughSymlink('cache/link/entry.json', 'cache')));
        self::assertFalse($this->fromRoot(static fn (): bool => SymlinkGuard::isThroughSymlink('cache/plain/entry.json', 'cache')));
    }

    public function test_a_symlink_above_the_root_is_left_alone(): void
    {
        $this->filesystem->mkdir($this->outside.'/project/build');
        symlink($this->outside, $this->root.'/link');
        $rootBehindSymlink = $this->root.'/link/project';

        self::assertFalse(SymlinkGuard::isThroughSymlink($rootBehindSymlink.'/build/report.json', $rootBehindSymlink));
        self::assertFalse(SymlinkGuard::isThroughSymlink($this->root.'/link/report.json', $this->root.'/link'));
    }

    public function test_a_path_outside_the_root_is_checked_for_its_file_and_directory_only(): void
    {
        symlink($this->outside, $this->root.'/build');

        self::assertFalse(SymlinkGuard::isThroughSymlink($this->root.'/build/reports/report.json', $this->outside));
        self::assertTrue(SymlinkGuard::isThroughSymlink($this->root.'/build/report.json', $this->outside));
    }

    public function test_the_process_working_directory_is_the_default_root(): void
    {
        $workingDirectory = getcwd();
        self::assertIsString($workingDirectory);
        $sandbox = $workingDirectory.'/var/symlink_guard_'.bin2hex(random_bytes(6));
        $this->filesystem->mkdir($sandbox);
        symlink($this->outside, $sandbox.'/build');

        try {
            self::assertTrue(SymlinkGuard::isThroughSymlink($sandbox.'/build/reports/report.json'));
            self::assertFalse(SymlinkGuard::isThroughSymlink($sandbox.'/build/reports/report.json', $this->outside));
        } finally {
            $this->filesystem->remove($sandbox);
        }
    }

    public function test_only_the_file_and_its_directory_are_checked_when_the_working_directory_is_gone(): void
    {
        $previousDirectory = getcwd();
        self::assertIsString($previousDirectory);
        $vanishingDirectory = sys_get_temp_dir().'/symlink_guard_gone_'.bin2hex(random_bytes(6));
        mkdir($vanishingDirectory);
        chdir($vanishingDirectory);
        rmdir($vanishingDirectory);

        try {
            self::assertFalse(SymlinkGuard::isThroughSymlink('report.json'));
        } finally {
            chdir($previousDirectory);
        }
    }

    public function test_a_dot_dot_segment_after_a_symlinked_directory_is_still_through_that_symlink(): void
    {
        $this->filesystem->mkdir($this->root.'/build');
        symlink($this->outside, $this->root.'/build/link');

        self::assertTrue(SymlinkGuard::isThroughSymlink($this->root.'/build/link/../report.sarif', $this->root));
        self::assertTrue($this->fromRoot(fn (): bool => SymlinkGuard::isThroughSymlink('build/link/../report.sarif', $this->root)));
    }

    public function test_a_dot_dot_segment_through_plain_directories_is_not_through_a_symlink(): void
    {
        $this->filesystem->mkdir($this->root.'/build/reports');

        self::assertFalse(SymlinkGuard::isThroughSymlink($this->root.'/build/reports/../report.json', $this->root));
        self::assertFalse($this->fromRoot(fn (): bool => SymlinkGuard::isThroughSymlink('build/../build/reports/report.json', $this->root)));
    }

    public function test_a_path_leaving_the_root_and_coming_back_is_checked_below_the_root_only(): void
    {
        $this->filesystem->mkdir($this->root.'/project');
        symlink($this->outside, $this->root.'/project/build');

        self::assertTrue(SymlinkGuard::isThroughSymlink($this->root.'/project/../project/build/report.json', $this->root.'/project'));
        self::assertFalse(SymlinkGuard::isThroughSymlink($this->root.'/project/../project/report.json', $this->root.'/project'));
    }

    public function test_a_dot_dot_that_escapes_above_the_root_after_a_symlinked_directory_is_still_through_that_symlink(): void
    {
        symlink($this->outside, $this->root.'/build');

        self::assertTrue(SymlinkGuard::isThroughSymlink($this->root.'/build/../../elsewhere/report.sarif', $this->root));
        self::assertTrue($this->fromRoot(fn (): bool => SymlinkGuard::isThroughSymlink('build/../../elsewhere/report.sarif', $this->root)));
    }

    /**
     * @param Closure(): bool $check
     */
    private function fromRoot(Closure $check): bool
    {
        $previousDirectory = getcwd();
        self::assertIsString($previousDirectory);
        chdir($this->root);

        try {
            return $check();
        } finally {
            chdir($previousDirectory);
        }
    }
}
