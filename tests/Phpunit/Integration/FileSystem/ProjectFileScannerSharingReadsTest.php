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
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\SplFileInfo;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;

final class ProjectFileScannerSharingReadsTest extends TestCase
{
    private Filesystem $filesystem;

    private string $project;

    /** @var list<string> */
    private array $reads = [];

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->project = sys_get_temp_dir().'/scanner_sharing_reads_'.bin2hex(random_bytes(6));
        $this->filesystem->mkdir($this->project);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->project);
    }

    public function test_a_file_two_scans_of_a_scanner_sharing_its_reads_reach_is_read_once(): void
    {
        $this->put('src/Controller/HomeController.php');
        $this->put('config/services.yaml', 'services: {}');
        $projectFileScanner = (new ProjectFileScanner(new NullLogger(), ['src', 'config'], fileReader: $this->recordingReader()))->sharingReads();

        $projectFileScan = $projectFileScanner->scanReportingSkippedFiles($this->project);
        $within = $projectFileScanner->scanReportingSkippedFiles($this->project, ['src/Controller']);

        sort($this->reads);
        self::assertSame(
            [['config/services.yaml', 'src/Controller/HomeController.php'], ['src/Controller/HomeController.php'], ['HomeController.php', 'services.yaml']],
            [$this->relativePaths($projectFileScan->files), $this->relativePaths($within->files), $this->reads],
        );
    }

    public function test_a_file_spelled_two_ways_by_two_scans_of_a_scanner_sharing_its_reads_is_read_once(): void
    {
        $this->put('src/App.php');
        $projectFileScanner = (new ProjectFileScanner(new NullLogger(), ['./src/App.php'], fileReader: $this->recordingReader()))->sharingReads();

        $projectFileScanner->scan($this->project);
        $projectFileScanner->scanWithin($this->project, ['src']);

        self::assertSame(['App.php'], $this->reads);
    }

    public function test_each_scanner_sharing_reads_reads_the_files_afresh(): void
    {
        $this->put('src/App.php', '<?php // first run');
        $projectFileScanner = new ProjectFileScanner(new NullLogger(), ['src']);
        $firstRun = $projectFileScanner->sharingReads()->scan($this->project);
        $this->put('src/App.php', '<?php // second run');

        $secondRun = $projectFileScanner->sharingReads()->scan($this->project);

        self::assertSame(['<?php // first run', '<?php // second run'], [$firstRun[0]->content(), $secondRun[0]->content()]);
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_a_scanner_sharing_its_reads_applies_the_rules_of_the_scanner_it_comes_from(): void
    {
        $this->put('src/App.php', "<?php\n\$password = 'hunter2hunter2';\n");
        $this->put('src/Big.php', '<?php // '.str_repeat('x', 2048));
        $this->put('src/.hidden/Hidden.php');
        $this->put('src/.gitignore', "Generated.php\n");
        $this->put('src/Generated.php');
        $this->put('config/services.yaml', 'services: {}');
        $projectFileScanner = new ProjectFileScanner(
            new NullLogger(),
            ['src'],
            respectGitignore: true,
            maxFileSizeKb: 1,
            fileReader: static fn (SplFileInfo $splFile): string => $splFile->getContents().'// read',
            secretScrubber: new RegexSecretScrubber(),
            includeDotfiles: false,
        );

        $projectFileScan = $projectFileScanner->sharingReads()->scanReportingSkippedFiles($this->project);

        self::assertEquals($projectFileScanner->scanReportingSkippedFiles($this->project), $projectFileScan);
        self::assertSame(["<?php\n\$password = '***REDACTED:inline_assignment***';\n// read"], array_map(static fn (ProjectFile $projectFile): string => $projectFile->content(), $projectFileScan->files));
    }

    public function test_a_file_a_directory_and_its_own_path_both_reach_in_one_scan_is_read_once(): void
    {
        $this->put('src/App.php');

        $files = (new ProjectFileScanner(new NullLogger(), ['src', 'src/App.php'], fileReader: $this->recordingReader()))->scan($this->project);

        self::assertSame([['src/App.php'], ['App.php']], [$this->relativePaths($files), $this->reads]);
    }

    /**
     * @return Closure(SplFileInfo): string
     */
    private function recordingReader(): Closure
    {
        return function (SplFileInfo $splFile): string {
            $this->reads[] = $splFile->getFilename();

            return $splFile->getContents();
        };
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
