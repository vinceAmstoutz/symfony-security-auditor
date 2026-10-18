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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class ProjectFileScannerProbeTest extends TestCase
{
    private Filesystem $filesystem;

    private string $project;

    /** @var list<string> */
    private array $reads = [];

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->project = sys_get_temp_dir().'/scanner_probe_'.bin2hex(random_bytes(6));
        $this->filesystem->mkdir($this->project);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->project);
    }

    public function test_a_project_its_configured_scan_reaches_a_file_in_holds_one_though_no_file_is_read_or_scrubbed(): void
    {
        $this->put('lib/Legacy.php');
        $this->put('lib/Other.php');
        $secretScrubber = $this->createMock(SecretScrubberInterface::class);
        $secretScrubber->expects(self::never())->method('scrub');

        $reachesAFile = (new ProjectFileScanner(new NullLogger(), ['lib'], fileReader: $this->recordingReader(), secretScrubber: $secretScrubber))->reachesAFile($this->project);

        self::assertSame([true, []], [$reachesAFile, $this->reads]);
    }

    public function test_a_file_is_reached_whatever_it_holds_since_the_probe_never_looks_inside_one(): void
    {
        $this->put('lib/Mixed.php', "<?php\n\$id\xE9 = \$request->get('id');\n\$idé = (int) \$id\xE9;\n");

        self::assertTrue((new ProjectFileScanner(new NullLogger(), ['lib']))->reachesAFile($this->project));
    }

    public function test_a_file_the_configured_paths_name_one_by_one_is_reached(): void
    {
        $this->put('public/index.php');

        self::assertTrue((new ProjectFileScanner(new NullLogger(), ['public/index.php']))->reachesAFile($this->project));
    }

    public function test_a_project_none_of_whose_configured_paths_exists_holds_no_file(): void
    {
        $this->put('src/Kernel.php');

        self::assertFalse((new ProjectFileScanner(new NullLogger(), ['lib']))->reachesAFile($this->project));
    }

    public function test_a_file_of_a_type_the_scan_does_not_read_is_not_reached(): void
    {
        $this->put('lib/README.md', '# Legacy');

        self::assertFalse((new ProjectFileScanner(new NullLogger(), ['lib']))->reachesAFile($this->project));
    }

    public function test_a_symlinked_file_is_not_reached(): void
    {
        $this->put('vendor/Legacy.php');
        $this->filesystem->symlink($this->project.'/vendor/Legacy.php', $this->project.'/lib/Legacy.php');

        self::assertFalse((new ProjectFileScanner(new NullLogger(), ['lib']))->reachesAFile($this->project));
    }

    public function test_a_file_over_the_size_limit_is_not_reached(): void
    {
        $this->put('lib/Big.php', '<?php // '.str_repeat('x', 2048));

        self::assertFalse((new ProjectFileScanner(new NullLogger(), ['lib'], maxFileSizeKb: 1))->reachesAFile($this->project));
    }

    public function test_a_gitignored_file_is_not_reached_when_gitignore_is_respected(): void
    {
        $this->put('lib/.gitignore', "Generated.php\n");
        $this->put('lib/Generated.php');

        self::assertFalse((new ProjectFileScanner(new NullLogger(), ['lib'], respectGitignore: true))->reachesAFile($this->project));
    }

    public function test_the_probe_stops_at_the_first_file_the_scan_would_keep(): void
    {
        $this->put('lib/Legacy.php');
        $this->put("config/\xFF.yaml", 'parameters: {}');
        $warningCollectingLogger = new WarningCollectingLogger();

        $reachesAFile = (new ProjectFileScanner($warningCollectingLogger, ['lib', "config/\xFF.yaml"]))->reachesAFile($this->project);

        self::assertSame([true, []], [$reachesAFile, $warningCollectingLogger->warnings]);
    }

    public function test_the_probe_goes_on_past_a_file_the_scan_would_leave_out(): void
    {
        $this->put("config/\xFF.yaml", 'parameters: {}');
        $warningCollectingLogger = new WarningCollectingLogger();

        $reachesAFile = (new ProjectFileScanner($warningCollectingLogger, ['lib', "config/\xFF.yaml"]))->reachesAFile($this->project);

        self::assertSame([true, ['File name is not valid UTF-8, its invalid bytes were replaced']], [$reachesAFile, array_column($warningCollectingLogger->warnings, 0)]);
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

    private function put(string $relativePath, string $content = '<?php'): void
    {
        $this->filesystem->dumpFile($this->project.'/'.$relativePath, $content);
    }
}
