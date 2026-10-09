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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\LockfileSymlinkResolver;

final class LockfileSymlinkResolverTest extends TestCase
{
    private string $base;

    private string $projectDir;

    private string $lockfile;

    public function test_a_lockfile_that_is_not_a_symlink_is_read_where_it_is(): void
    {
        file_put_contents($this->lockfile, '{}');

        self::assertSame($this->lockfile, LockfileSymlinkResolver::resolve($this->lockfile, $this->projectDir));
    }

    public function test_a_symlink_to_a_regular_file_inside_the_project_is_read_at_its_target(): void
    {
        file_put_contents($this->projectDir.'/real.lock', '{}');
        symlink($this->projectDir.'/real.lock', $this->lockfile);

        self::assertSame(realpath($this->projectDir.'/real.lock'), LockfileSymlinkResolver::resolve($this->lockfile, $this->projectDir));
    }

    public function test_a_relative_symlink_into_a_sub_directory_of_the_project_is_followed(): void
    {
        mkdir($this->projectDir.'/docker', 0o777, true);
        file_put_contents($this->projectDir.'/docker/shared.lock', '{}');
        symlink('docker/shared.lock', $this->lockfile);

        self::assertSame(realpath($this->projectDir.'/docker/shared.lock'), LockfileSymlinkResolver::resolve($this->lockfile, $this->projectDir));
    }

    public function test_a_chain_of_symlinks_ending_inside_the_project_is_followed(): void
    {
        file_put_contents($this->projectDir.'/real.lock', '{}');
        symlink($this->projectDir.'/real.lock', $this->projectDir.'/middle.lock');
        symlink($this->projectDir.'/middle.lock', $this->lockfile);

        self::assertSame(realpath($this->projectDir.'/real.lock'), LockfileSymlinkResolver::resolve($this->lockfile, $this->projectDir));
    }

    public function test_a_project_reached_through_a_symlink_keeps_its_own_lockfile_links(): void
    {
        file_put_contents($this->projectDir.'/real.lock', '{}');
        symlink($this->projectDir.'/real.lock', $this->lockfile);
        symlink($this->projectDir, $this->base.'/current');

        self::assertSame(realpath($this->projectDir.'/real.lock'), LockfileSymlinkResolver::resolve($this->base.'/current/composer.lock', $this->base.'/current'));
    }

    public function test_a_symlink_to_a_file_outside_the_project_is_refused(): void
    {
        file_put_contents($this->base.'/outside.lock', '{}');
        symlink($this->base.'/outside.lock', $this->lockfile);

        self::assertNull(LockfileSymlinkResolver::resolve($this->lockfile, $this->projectDir));
    }

    public function test_a_symlink_to_a_file_of_a_sibling_directory_sharing_the_project_name_is_refused(): void
    {
        mkdir($this->projectDir.'-evil', 0o777, true);
        file_put_contents($this->projectDir.'-evil/real.lock', '{}');
        symlink($this->projectDir.'-evil/real.lock', $this->lockfile);

        self::assertNull(LockfileSymlinkResolver::resolve($this->lockfile, $this->projectDir));
    }

    public function test_a_symlink_to_a_device_is_refused(): void
    {
        symlink('/dev/zero', $this->lockfile);

        self::assertNull(LockfileSymlinkResolver::resolve($this->lockfile, $this->projectDir));
    }

    public function test_a_symlink_to_a_directory_inside_the_project_is_refused(): void
    {
        mkdir($this->projectDir.'/vendor', 0o777, true);
        symlink($this->projectDir.'/vendor', $this->lockfile);

        self::assertNull(LockfileSymlinkResolver::resolve($this->lockfile, $this->projectDir));
    }

    #[Override]
    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/lockfile_symlink_resolver_'.uniqid('', true);
        $this->projectDir = $this->base.'/project';
        $this->lockfile = $this->projectDir.'/composer.lock';
        mkdir($this->projectDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->base);
    }
}
