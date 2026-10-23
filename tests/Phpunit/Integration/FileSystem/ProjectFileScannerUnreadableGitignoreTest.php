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
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class ProjectFileScannerUnreadableGitignoreTest extends TestCase
{
    private Filesystem $filesystem;

    private string $project;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->project = sys_get_temp_dir().'/scanner_unreadable_gitignore_'.bin2hex(random_bytes(6));
        $this->filesystem->mkdir($this->project.'/src/Controller/.gitignore');
        $this->put('src/Controller/.gitignore/keep', 'keep');
        $this->put('src/Controller/HomeController.php');
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->project);
    }

    public function test_a_directory_named_gitignore_holds_no_rule_and_the_scan_goes_on(): void
    {
        self::assertSame(['src/Controller/HomeController.php'], $this->scannedPaths());
    }

    public function test_it_warns_once_about_a_gitignore_that_holds_no_rule(): void
    {
        $this->put('src/Controller/OtherController.php');
        $warningCollectingLogger = new WarningCollectingLogger();

        $this->scannedPaths($warningCollectingLogger);

        self::assertSame([['Read no rule from a .gitignore that is not a file', ['path' => $this->project.'/src/Controller/.gitignore']]], $warningCollectingLogger->warnings);
    }

    public function test_the_rules_of_the_other_gitignore_files_still_apply(): void
    {
        $this->put('src/.gitignore', "Generated.php\n");
        $this->put('src/Controller/Generated.php');

        self::assertSame(['src/Controller/HomeController.php'], $this->scannedPaths());
    }

    public function test_the_deepest_gitignore_with_a_matching_rule_decides(): void
    {
        $this->put('src/.gitignore', "Keep.php\n");
        $this->put('src/Controller/Sub/.gitignore', "!Keep.php\n");
        $this->put('src/Controller/Keep.php');
        $this->put('src/Controller/Sub/Keep.php');

        self::assertSame(['src/Controller/HomeController.php', 'src/Controller/Sub/Keep.php'], $this->scannedPaths());
    }

    public function test_the_last_matching_rule_of_a_gitignore_decides(): void
    {
        $this->put('src/.gitignore', "Gen*.php\n!GenKept.php\n");
        $this->put('src/Controller/GenKept.php');
        $this->put('src/Controller/GenOther.php');

        self::assertSame(['src/Controller/GenKept.php', 'src/Controller/HomeController.php'], $this->scannedPaths());
    }

    public function test_an_ignored_directory_takes_its_files_with_it(): void
    {
        $this->put('src/.gitignore', "Generated/\n!Kept.php\n");
        $this->put('src/Controller/Generated/A.php');
        $this->put('src/Controller/Generated/Kept.php');

        self::assertSame(['src/Controller/HomeController.php'], $this->scannedPaths());
    }

    public function test_a_directory_only_rule_ignores_a_directory_and_not_a_file_of_that_name(): void
    {
        $this->put('src/.gitignore', "Cache.php/\n");
        $this->put('src/Controller/Cache.php/A.php');
        $this->put('src/Controller/Sub/Cache.php');

        self::assertSame(['src/Controller/HomeController.php', 'src/Controller/Sub/Cache.php'], $this->scannedPaths());
    }

    public function test_a_rule_matching_only_the_start_of_a_path_does_not_decide(): void
    {
        $this->put('src/Controller/Sub/.gitignore', "*.php\n!Keep\n");
        $this->put('src/Controller/Sub/Keep/A.php');

        self::assertSame(['src/Controller/HomeController.php'], $this->scannedPaths());
    }

    public function test_a_comment_holds_no_rule_while_an_escaped_or_negated_hash_does(): void
    {
        $this->put('src/.gitignore', "\\#*.php\n!#Back.php\n");
        $this->put('src/Controller/Sub/.gitignore', "#Commented.php\n");
        $this->put('src/Controller/#Back.php');
        $this->put('src/Controller/#Other.php');
        $this->put('src/Controller/Sub/Commented.php');

        self::assertSame(['src/Controller/#Back.php', 'src/Controller/HomeController.php', 'src/Controller/Sub/Commented.php'], $this->scannedPaths());
    }

    public function test_the_line_break_and_trailing_spaces_of_a_rule_are_left_out_before_it_is_read(): void
    {
        $this->put('src/.gitignore', "Spaced.php   \r\nCache.php/   \r\n");
        $this->put('src/Controller/Spaced.php');
        $this->put('src/Controller/Cache.php/A.php');
        $this->put('src/Controller/Sub/Cache.php');

        self::assertSame(['src/Controller/HomeController.php', 'src/Controller/Sub/Cache.php'], $this->scannedPaths());
    }

    public function test_the_gitignore_files_of_the_git_repository_holding_the_project_apply(): void
    {
        $this->filesystem->mkdir($this->project.'/.git');

        self::assertSame(['src/Controller/HomeController.php'], $this->scannedPathsOfAnAppWhoseParentIgnores('app/src/Controller/Rooted.php'));
    }

    public function test_the_gitignore_files_of_a_git_repository_two_levels_above_the_project_apply(): void
    {
        $this->filesystem->mkdir($this->project.'/.git');
        $this->filesystem->mirror($this->project.'/src', $this->project.'/apps/app/src');
        $this->put('.gitignore', "apps/app/src/Controller/Rooted.php\n");
        $this->put('apps/app/src/Controller/Rooted.php');

        self::assertSame(['src/Controller/HomeController.php'], $this->relativePaths((new ProjectFileScanner(new NullLogger(), ['src'], respectGitignore: true))->scan($this->project.'/apps/app')));
    }

    public function test_a_project_that_is_a_git_repository_of_its_own_leaves_out_the_rules_of_the_repository_around_it(): void
    {
        $this->filesystem->mkdir([$this->project.'/.git', $this->project.'/app/.git']);

        self::assertSame(['src/Controller/HomeController.php', 'src/Controller/Rooted.php'], $this->scannedPathsOfAnAppWhoseParentIgnores('app/src/Controller/Rooted.php'));
    }

    public function test_a_gitignore_above_a_project_outside_any_git_repository_does_not_apply(): void
    {
        self::assertSame(['src/Controller/HomeController.php', 'src/Controller/Rooted.php'], $this->scannedPathsOfAnAppWhoseParentIgnores('app/src/Controller/Rooted.php'));
    }

    public function test_a_project_reached_through_a_symlink_has_its_rules_applied(): void
    {
        $this->put('src/.gitignore', "Generated.php\n");
        $this->put('src/Controller/Generated.php');
        $link = sys_get_temp_dir().'/linked_project_'.bin2hex(random_bytes(6));
        $this->filesystem->symlink($this->project, $link);

        try {
            $files = (new ProjectFileScanner(new NullLogger(), ['src'], respectGitignore: true))->scan($link);
        } finally {
            $this->filesystem->remove($link);
        }

        self::assertSame(['src/Controller/HomeController.php'], $this->relativePaths($files));
    }

    public function test_a_project_inside_a_symlinked_directory_has_its_rules_applied(): void
    {
        $this->put('src/.gitignore', "Generated.php\n");
        $this->put('src/Controller/Generated.php');
        $link = sys_get_temp_dir().'/linked_parent_'.bin2hex(random_bytes(6));
        $this->filesystem->symlink(\dirname($this->project), $link);

        try {
            $files = (new ProjectFileScanner(new NullLogger(), ['src'], respectGitignore: true))->scan($link.'/'.basename($this->project));
        } finally {
            $this->filesystem->remove($link);
        }

        self::assertSame(['src/Controller/HomeController.php'], $this->relativePaths($files));
    }

    public function test_a_directory_whose_name_holds_a_backslash_keeps_its_gitignore(): void
    {
        $this->put('src/Controller/we\\ird/.gitignore', "Hidden.php\n");
        $this->put('src/Controller/we\\ird/Hidden.php');

        self::assertSame(['src/Controller/HomeController.php'], $this->scannedPaths());
    }

    /**
     * @return list<string>
     */
    private function scannedPaths(LoggerInterface $logger = new NullLogger()): array
    {
        return $this->relativePaths((new ProjectFileScanner($logger, ['src'], respectGitignore: true))->scan($this->project));
    }

    /**
     * @return list<string>
     */
    private function scannedPathsOfAnAppWhoseParentIgnores(string $path): array
    {
        $this->filesystem->mirror($this->project.'/src', $this->project.'/app/src');
        $this->put('.gitignore', $path."\n");
        $this->put('app/src/Controller/Rooted.php');

        return $this->relativePaths((new ProjectFileScanner(new NullLogger(), ['src'], respectGitignore: true))->scan($this->project.'/app'));
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<string>
     */
    private function relativePaths(array $files): array
    {
        return array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);
    }

    private function put(string $relativePath, string $content = '<?php'): void
    {
        $this->filesystem->dumpFile($this->project.'/'.$relativePath, $content);
    }
}
