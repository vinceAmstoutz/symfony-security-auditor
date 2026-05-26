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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Diff;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\GitChangedFilesUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Diff\ProcessGitChangedFilesResolver;

final class ProcessGitChangedFilesResolverTest extends TestCase
{
    private string $tmpDir;

    private Filesystem $filesystem;

    public function test_it_throws_when_directory_is_not_a_git_tree(): void
    {
        $this->expectException(GitChangedFilesUnavailableException::class);

        (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'main');
    }

    public function test_it_throws_when_ref_does_not_exist_in_repo(): void
    {
        $this->initRepo();

        $this->expectException(GitChangedFilesUnavailableException::class);

        (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'does-not-exist');
    }

    public function test_it_returns_files_changed_against_ref(): void
    {
        $this->initRepo();
        $this->commit('src/Foo.php', '<?php // initial', 'init');
        $this->createBranch('feature');
        $this->commit('src/Bar.php', '<?php // new', 'add bar');

        $changed = (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'main');

        self::assertContains('src/Bar.php', $changed);
        self::assertNotContains('src/Foo.php', $changed);
    }

    public function test_it_includes_uncommitted_changes_against_head(): void
    {
        $this->initRepo();
        $this->commit('src/Foo.php', '<?php // initial', 'init');
        $this->writeFile('src/Bar.php', '<?php // uncommitted');
        $this->stage('src/Bar.php');

        $changed = (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'HEAD');

        self::assertContains('src/Bar.php', $changed);
    }

    public function test_returned_paths_are_sorted_for_determinism(): void
    {
        $this->initRepo();
        $this->commit('src/Z.php', '<?php', 'z');
        $this->createBranch('feature');
        $this->commit('src/A.php', '<?php', 'a');
        $this->commit('src/M.php', '<?php', 'm');

        $changed = (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'main');
        $changedFiltered = array_values(array_filter($changed, static fn (string $p): bool => str_starts_with($p, 'src/')));

        self::assertSame(['src/A.php', 'src/M.php'], $changedFiltered);
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/git_diff_resolver_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
        $this->filesystem = new Filesystem();
    }

    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    private function initRepo(): void
    {
        $this->runGit(['git', 'init', '--initial-branch=main']);
        $this->runGit(['git', 'config', 'user.email', 'test@example.com']);
        $this->runGit(['git', 'config', 'user.name', 'Test']);
        $this->runGit(['git', 'config', 'commit.gpgsign', 'false']);
    }

    private function commit(string $relativePath, string $content, string $message): void
    {
        $this->writeFile($relativePath, $content);
        $this->stage($relativePath);
        $this->runGit(['git', 'commit', '-m', $message]);
    }

    private function createBranch(string $name): void
    {
        $this->runGit(['git', 'checkout', '-b', $name]);
    }

    private function writeFile(string $relativePath, string $content): void
    {
        $absolute = $this->tmpDir.'/'.$relativePath;
        $this->filesystem->mkdir(\dirname($absolute));
        file_put_contents($absolute, $content);
    }

    private function stage(string $relativePath): void
    {
        $this->runGit(['git', 'add', $relativePath]);
    }

    /** @param list<string> $argv */
    private function runGit(array $argv): void
    {
        $process = new Process($argv, $this->tmpDir);
        $process->mustRun();
    }
}
