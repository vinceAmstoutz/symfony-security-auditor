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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileScan;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SkippedFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SkippedFileReason;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class ProjectFileScannerSymlinkTest extends TestCase
{
    private Filesystem $filesystem;

    private string $project;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->project = sys_get_temp_dir().'/scanner_symlink_'.bin2hex(random_bytes(6));
        $this->filesystem->dumpFile($this->project.'/src/Controller/HomeController.php', '<?php');
        $this->filesystem->dumpFile($this->project.'/lib/AdminController.php', '<?php');
        $this->filesystem->dumpFile($this->project.'/lib/Admin/UserController.php', '<?php');
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->project);
    }

    public function test_a_symlinked_file_is_left_out_as_a_symbolic_link_and_named_in_a_warning(): void
    {
        $this->link('lib/AdminController.php', 'src/Controller/AdminController.php');
        $warningCollectingLogger = new WarningCollectingLogger();

        $projectFileScan = $this->scan($warningCollectingLogger);

        self::assertSame([['src/Controller/HomeController.php'], [['src/Controller/AdminController.php', SkippedFileReason::Symlink]]], $this->outcome($projectFileScan));
        self::assertSame([['Skipped symlinked file', ['path' => $this->project.'/src/Controller/AdminController.php']]], $warningCollectingLogger->warnings);
    }

    public function test_a_symlinked_directory_is_left_out_as_a_symbolic_link_and_named_in_a_warning(): void
    {
        $this->link('lib/Admin', 'src/Controller/Admin');
        $warningCollectingLogger = new WarningCollectingLogger();

        $projectFileScan = $this->scan($warningCollectingLogger);

        self::assertSame([['src/Controller/HomeController.php'], [['src/Controller/Admin', SkippedFileReason::Symlink]]], $this->outcome($projectFileScan));
        self::assertSame([['Skipped symlinked directory', ['path' => $this->project.'/src/Controller/Admin']]], $warningCollectingLogger->warnings);
    }

    public function test_an_included_path_that_is_a_symlink_is_left_out_as_a_symbolic_link(): void
    {
        $this->link('lib/AdminController.php', '.env.local');
        $this->link('lib/Admin', 'modules');

        self::assertSame(
            [['src/Controller/HomeController.php'], [['.env.local', SkippedFileReason::Symlink], ['modules', SkippedFileReason::Symlink]]],
            $this->outcome((new ProjectFileScanner(new NullLogger(), ['src', 'modules', '.env.local']))->scanReportingSkippedFiles($this->project)),
        );
    }

    public function test_scan_paths_that_are_only_symlinks_are_each_left_out_once_as_a_symbolic_link(): void
    {
        $this->link('lib/AdminController.php', '.env.local');
        $this->link('lib/Admin', "mod\xFFules");

        self::assertSame(
            [[], [['.env.local', SkippedFileReason::Symlink], ["mod\u{FF}ules", SkippedFileReason::Symlink]]],
            $this->outcome((new ProjectFileScanner(new NullLogger(), ['src']))->scanReportingSkippedFiles($this->project, ["mod\xFFules", '.env.local', "./mod\xFFules"])),
        );
    }

    /**
     * @param list<string> $includedPaths
     */
    #[DataProvider('directoriesListedInsideAnother')]
    public function test_a_directory_listed_inside_another_listed_one_is_walked_once(array $includedPaths): void
    {
        $this->link('lib/AdminController.php', 'src/Controller/Admin/AdminController.php');
        $warningCollectingLogger = new WarningCollectingLogger();

        (new ProjectFileScanner($warningCollectingLogger, $includedPaths))->scanReportingSkippedFiles($this->project);

        self::assertSame([['Skipped symlinked file', ['path' => $this->project.'/src/Controller/Admin/AdminController.php']]], $warningCollectingLogger->warnings);
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function directoriesListedInsideAnother(): iterable
    {
        yield 'its parent listed before it' => [['src/Controller', 'src/Controller/Admin']];
        yield 'its parent listed after it' => [['src/Controller/Admin', 'src/Controller']];
        yield 'a farther ancestor listed' => [['src', 'src/Controller/Admin']];
    }

    public function test_a_symlinked_directory_is_reported_under_its_repaired_name(): void
    {
        $this->link('lib/Admin', "src/Controller/Adm\xFFin");

        self::assertSame([['src/Controller/HomeController.php'], [["src/Controller/Adm\u{FF}in", SkippedFileReason::Symlink]]], $this->outcome($this->scan()));
    }

    /**
     * @param list<array{string, SkippedFileReason}> $expectedSkippedFiles
     */
    #[DataProvider('dotFileSettings')]
    public function test_a_symlinked_directory_inside_a_dot_directory_is_reported_only_when_dot_files_are_read(bool $includeDotfiles, array $expectedSkippedFiles): void
    {
        $this->link('lib/Admin', 'src/.hidden/Admin');

        self::assertSame($expectedSkippedFiles, $this->outcome((new ProjectFileScanner(new NullLogger(), ['src'], includeDotfiles: $includeDotfiles))->scanReportingSkippedFiles($this->project))[1]);
    }

    /**
     * @return iterable<string, array{bool, list<array{string, SkippedFileReason}>}>
     */
    public static function dotFileSettings(): iterable
    {
        yield 'dot files left out' => [false, []];
        yield 'dot files read' => [true, [['src/.hidden/Admin', SkippedFileReason::Symlink]]];
    }

    /**
     * @param list<array{string, SkippedFileReason}> $expectedSkippedFiles
     */
    #[DataProvider('gitignoreSettings')]
    public function test_a_symlinked_directory_onto_one_a_gitignore_of_the_repository_ignores_is_reported_only_when_gitignore_is_not_respected(bool $respectGitignore, array $expectedSkippedFiles): void
    {
        $this->filesystem->mkdir($this->project.'/.git');
        $this->filesystem->dumpFile($this->project.'/src/.gitignore', "Generated/\n");
        $this->filesystem->dumpFile($this->project.'/src/Generated/Proxy.php', '<?php');
        $this->link('src/Generated', 'src/Controller/Proxies');

        self::assertSame($expectedSkippedFiles, $this->outcome((new ProjectFileScanner(new NullLogger(), ['src/Controller'], respectGitignore: $respectGitignore))->scanReportingSkippedFiles($this->project))[1]);
    }

    /**
     * @return iterable<string, array{bool, list<array{string, SkippedFileReason}>}>
     */
    public static function gitignoreSettings(): iterable
    {
        yield 'gitignore respected' => [true, []];
        yield 'gitignore not respected' => [false, [['src/Controller/Proxies', SkippedFileReason::Symlink]]];
    }

    public function test_a_symlinked_directory_onto_one_beside_a_gitignore_that_is_not_a_file_is_still_reported(): void
    {
        $this->filesystem->mkdir([$this->project.'/.git', $this->project.'/src/Controller/.gitignore', $this->project.'/src/Controller/Admin']);
        $this->link('src/Controller/Admin', 'src/Legacy/Admin');

        self::assertSame([['src/Controller/HomeController.php'], [['src/Legacy/Admin', SkippedFileReason::Symlink]]], $this->outcome((new ProjectFileScanner(new NullLogger(), ['src'], respectGitignore: true))->scanReportingSkippedFiles($this->project)));
    }

    private function scan(WarningCollectingLogger $warningCollectingLogger = new WarningCollectingLogger()): ProjectFileScan
    {
        return (new ProjectFileScanner($warningCollectingLogger, ['src']))->scanReportingSkippedFiles($this->project);
    }

    /**
     * @return array{list<string>, list<array{string, SkippedFileReason}>}
     */
    private function outcome(ProjectFileScan $projectFileScan): array
    {
        return [
            array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $projectFileScan->files),
            array_map(static fn (SkippedFile $skippedFile): array => [$skippedFile->relativePath, $skippedFile->reason], $projectFileScan->skippedFiles),
        ];
    }

    private function link(string $target, string $link): void
    {
        $this->filesystem->mkdir(\dirname($this->project.'/'.$link));
        symlink($this->project.'/'.$target, $this->project.'/'.$link);
    }
}
