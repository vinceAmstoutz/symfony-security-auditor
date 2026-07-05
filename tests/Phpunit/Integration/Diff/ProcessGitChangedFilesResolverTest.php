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

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\GitChangedFilesUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Diff\ProcessGitChangedFilesResolver;

final class ProcessGitChangedFilesResolverTest extends TestCase
{
    private string $tmpDir;

    private Filesystem $filesystem;

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_it_throws_when_directory_is_not_a_git_tree(): void
    {
        $this->expectException(GitChangedFilesUnavailableException::class);
        $this->expectExceptionMessage('is not a git working tree');

        (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'main');
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_it_throws_when_ref_does_not_exist_in_repo(): void
    {
        $this->initRepo();

        $this->expectException(GitChangedFilesUnavailableException::class);
        $this->expectExceptionMessage('does not resolve');

        (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'does-not-exist');
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_merged_committed_and_uncommitted_paths_are_sorted(): void
    {
        $this->initRepo();
        $this->commit('src/Z.php', '<?php', 'z');
        $this->createBranch('feature');
        $this->commit('src/B.php', '<?php', 'committed b');
        $this->writeFile('src/A.php', '<?php // uncommitted');
        $this->stage('src/A.php');

        $changed = (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'main');
        $srcChanged = array_values(array_filter($changed, static fn (string $path): bool => str_starts_with($path, 'src/')));

        self::assertSame(['src/A.php', 'src/B.php'], $srcChanged);
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_a_path_changed_in_both_committed_and_uncommitted_diffs_is_deduplicated(): void
    {
        $this->initRepo();
        $this->commit('src/Foo.php', '<?php // initial', 'init');
        $this->createBranch('feature');
        $this->commit('src/Shared.php', '<?php // committed change', 'add shared');
        $this->writeFile('src/Shared.php', '<?php // committed change + uncommitted edit');
        $this->stage('src/Shared.php');

        $changed = (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'main');
        $shared = array_values(array_filter($changed, static fn (string $path): bool => 'src/Shared.php' === $path));

        self::assertSame(['src/Shared.php'], $shared);
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
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

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_it_includes_a_changed_dotfile(): void
    {
        $this->initRepo();
        $this->commit('src/Foo.php', '<?php // initial', 'init');
        $this->createBranch('feature');
        $this->commit('.env', 'APP_SECRET=changed', 'add env');

        $changed = (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'main');

        self::assertContains('.env', $changed);
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_it_includes_uncommitted_changes_against_head(): void
    {
        $this->initRepo();
        $this->commit('src/Foo.php', '<?php // initial', 'init');
        $this->writeFile('src/Bar.php', '<?php // uncommitted');
        $this->stage('src/Bar.php');

        $changed = (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'HEAD');

        self::assertContains('src/Bar.php', $changed);
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
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

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_it_resolves_from_a_subdirectory_where_dot_git_is_not_present(): void
    {
        $this->initRepo();
        $this->commit('src/Foo.php', '<?php // initial', 'init');
        $this->createBranch('feature');
        $this->commit('src/sub/Bar.php', '<?php // new', 'add bar');

        // From src/ there is no .git; the resolver must rely on `git rev-parse
        // --is-inside-work-tree` to recognise it as a working tree rather than
        // throwing. Any mutation that breaks that detection makes this throw.
        $changed = (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir.'/src', 'main');

        self::assertContains('src/sub/Bar.php', $changed);
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_it_relies_on_rev_parse_when_a_dot_git_path_exists_but_is_not_a_repo(): void
    {
        $this->filesystem->mkdir($this->tmpDir.'/.git');

        $this->expectException(GitChangedFilesUnavailableException::class);
        $this->expectExceptionMessage('does not resolve');

        (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'main');
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_it_throws_for_a_path_inside_the_git_directory_not_the_work_tree(): void
    {
        $this->initRepo();
        $this->commit('src/Foo.php', '<?php', 'init');

        $this->expectException(GitChangedFilesUnavailableException::class);
        $this->expectExceptionMessage('is not a git working tree');

        (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir.'/.git', 'main');
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_it_diffs_branch_commits_since_merge_base_not_the_raw_ref_diff(): void
    {
        $this->initRepo();
        $this->commit('src/Foo.php', '<?php // v1', 'init');
        $this->createBranch('feature');
        $this->commit('src/Bar.php', '<?php // bar', 'add bar');
        $this->runGit(['git', 'checkout', 'main']);
        $this->commit('src/Foo.php', '<?php // v2 changed on main', 'change foo on main');
        $this->runGit(['git', 'checkout', 'feature']);

        $changed = (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'main');

        self::assertContains('src/Bar.php', $changed);
        self::assertNotContains('src/Foo.php', $changed);
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    public function test_it_wraps_a_git_diff_process_failure_when_the_ref_resolves_but_has_no_merge_base(): void
    {
        $this->initRepo();
        $this->commit('src/Foo.php', '<?php', 'on main');
        $this->runGit(['git', 'checkout', '--orphan', 'unrelated']);
        $this->commit('src/Bar.php', '<?php', 'unrelated root');

        $this->expectException(GitChangedFilesUnavailableException::class);
        $this->expectExceptionMessage('git diff against "main...HEAD" failed');

        (new ProcessGitChangedFilesResolver())->changedSince($this->tmpDir, 'main');
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/git_diff_resolver_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
        $this->filesystem = new Filesystem();
    }

    #[Override]
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
