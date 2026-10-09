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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Pipeline;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\ErrorHandler\BufferingLogger;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\SplFileInfo;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;

final class IngestionStageSkippedFilesTest extends TestCase
{
    private string $tmpDir;

    private Filesystem $filesystem;

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_file_over_the_size_limit_is_recorded_as_skipped_and_leaves_the_report_complete(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Small.php', '<?php class Small {}');
        file_put_contents($this->tmpDir.'/src/Big.php', '<?php /* '.str_repeat('x', 600 * 1024).' */');

        $auditContext = AuditContext::forProject($this->tmpDir);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 512), new NullLogger()))->process($auditContext);

        $auditReport = AuditReport::fromContext($auditContext);
        self::assertSame([['stage' => 'scan', 'file' => 'src/Big.php', 'status' => 'skipped']], $auditContext->coverage());
        self::assertSame([], $auditReport->unanalyzedFiles());
        self::assertTrue($auditReport->isComplete());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_file_under_the_size_limit_leaves_the_report_complete(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Small.php', '<?php class Small {}');

        $auditContext = AuditContext::forProject($this->tmpDir);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 512), new NullLogger()))->process($auditContext);

        self::assertSame([], $auditContext->coverage());
        self::assertTrue(AuditReport::fromContext($auditContext)->isComplete());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_file_exactly_at_the_size_limit_is_analyzed_and_one_byte_over_is_not(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/AtLimit.php', str_repeat('a', 2 * 1024));
        file_put_contents($this->tmpDir.'/src/OneByteOver.php', str_repeat('a', (2 * 1024) + 1));

        $auditContext = AuditContext::forProject($this->tmpDir);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2), new NullLogger()))->process($auditContext);

        self::assertSame([['stage' => 'scan', 'file' => 'src/OneByteOver.php', 'status' => 'skipped']], $auditContext->coverage());
        self::assertSame(['src/AtLimit.php'], $this->analyzedPaths($auditContext));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_an_explicit_file_over_the_size_limit_is_recorded_as_skipped(): void
    {
        mkdir($this->tmpDir.'/public', 0o777, true);
        file_put_contents($this->tmpDir.'/public/index.php', str_repeat('a', (2 * 1024) + 1));

        $auditContext = AuditContext::forProject($this->tmpDir);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2), new NullLogger()))->process($auditContext);

        self::assertSame([['stage' => 'scan', 'file' => 'public/index.php', 'status' => 'skipped']], $auditContext->coverage());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_file_the_scanner_could_not_read_is_recorded_as_skipped_and_leaves_the_report_complete(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Readable.php', '<?php');
        file_put_contents($this->tmpDir.'/src/Unreadable.php', '<?php');
        $reader = static function (SplFileInfo $splFile): string {
            if (str_ends_with($splFile->getPathname(), 'Unreadable.php')) {
                throw new RuntimeException('disk read error');
            }

            return $splFile->getContents();
        };

        $auditContext = AuditContext::forProject($this->tmpDir);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), fileReader: $reader), new NullLogger()))->process($auditContext);

        $auditReport = AuditReport::fromContext($auditContext);
        self::assertSame([['stage' => 'scan', 'file' => 'src/Unreadable.php', 'status' => 'skipped']], $auditContext->coverage());
        self::assertSame([], $auditReport->unanalyzedFiles());
        self::assertTrue($auditReport->isComplete());
        self::assertSame(['src/Readable.php'], $this->analyzedPaths($auditContext));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_two_files_whose_names_are_the_same_once_repaired_leave_the_report_complete_and_say_why(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir."/src/caf\xE9.php", '<?php class A {}');
        file_put_contents($this->tmpDir."/src/caf\xE8.php", '<?php class B {}');

        $bufferingLogger = new BufferingLogger();
        $auditContext = AuditContext::forProject($this->tmpDir);
        (new IngestionStage(new ProjectFileScanner(new NullLogger()), $bufferingLogger))->process($auditContext);

        $auditReport = AuditReport::fromContext($auditContext);
        self::assertSame([['stage' => 'scan', 'file' => "src/caf\u{FFFD}.php", 'status' => 'skipped']], $auditContext->coverage());
        self::assertSame([], $auditReport->unanalyzedFiles());
        self::assertTrue($auditReport->isComplete());
        self::assertSame(["src/caf\u{FFFD}.php"], $this->analyzedPaths($auditContext));
        self::assertContains(
            ['warning', 'The scan left a file out, so it is not analyzed', ['file' => "src/caf\u{FFFD}.php", 'reason' => "its name is the same as another file's once the bytes that are not valid UTF-8 are replaced"]],
            $bufferingLogger->cleanLogs(),
        );
    }

    /**
     * @param callable(string): void $arrange builds the excluded file(s) under the project root
     *
     * @throws InvalidAuditContextException
     */
    #[DataProvider('exclusionsTheScannerMakesOnPurpose')]
    public function test_a_file_the_scan_excludes_on_purpose_leaves_the_report_complete(callable $arrange, bool $respectGitignore): void
    {
        $arrange($this->tmpDir);

        $auditContext = AuditContext::forProject($this->tmpDir);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), respectGitignore: $respectGitignore, maxFileSizeKb: 2), new NullLogger()))->process($auditContext);

        self::assertSame([], $auditContext->coverage());
        self::assertTrue(AuditReport::fromContext($auditContext)->isComplete());
    }

    /** @return iterable<string, array{callable(string): void, bool}> */
    public static function exclusionsTheScannerMakesOnPurpose(): iterable
    {
        $oversized = str_repeat('a', (2 * 1024) + 1);

        yield 'a gitignored file' => [
            static function (string $root) use ($oversized): void {
                mkdir($root.'/src', 0o777, true);
                file_put_contents($root.'/src/.gitignore', "Ignored.php\n");
                file_put_contents($root.'/src/Ignored.php', $oversized);
            },
            true,
        ];
        yield 'a file in a dot-directory' => [
            static function (string $root) use ($oversized): void {
                mkdir($root.'/src/.hidden', 0o777, true);
                file_put_contents($root.'/src/.hidden/Big.php', $oversized);
            },
            false,
        ];
        yield 'a file the scanner does not track' => [
            static function (string $root) use ($oversized): void {
                mkdir($root.'/src', 0o777, true);
                file_put_contents($root.'/src/data.json', $oversized);
            },
            false,
        ];
        yield 'a file outside the included paths' => [
            static function (string $root) use ($oversized): void {
                mkdir($root.'/vendor/acme', 0o777, true);
                mkdir($root.'/var/cache', 0o777, true);
                file_put_contents($root.'/vendor/acme/Big.php', $oversized);
                file_put_contents($root.'/var/cache/Big.php', $oversized);
            },
            false,
        ];
        yield 'a symlinked file' => [
            static function (string $root) use ($oversized): void {
                mkdir($root.'/src', 0o777, true);
                file_put_contents($root.'/Target.php', $oversized);
                symlink($root.'/Target.php', $root.'/src/Link.php');
            },
            false,
        ];
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_file_over_the_size_limit_outside_the_path_scope_is_not_recorded(): void
    {
        mkdir($this->tmpDir.'/src/Admin', 0o777, true);
        mkdir($this->tmpDir.'/src/Billing', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Admin/Big.php', str_repeat('a', (2 * 1024) + 1));
        file_put_contents($this->tmpDir.'/src/Billing/Big.php', str_repeat('a', (2 * 1024) + 1));

        $auditContext = AuditContext::forProject($this->tmpDir, ['src/Admin']);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2), new NullLogger()))->process($auditContext);

        self::assertSame([['stage' => 'scan', 'file' => 'src/Admin/Big.php', 'status' => 'skipped']], $auditContext->coverage());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_path_replaces_the_configured_scan_surface_for_the_files_it_leaves_out(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/apps/api', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Big.php', str_repeat('a', (2 * 1024) + 1));
        file_put_contents($this->tmpDir.'/apps/api/Big.php', str_repeat('a', (2 * 1024) + 1));

        $auditContext = AuditContext::forProject($this->tmpDir, ['./apps/api/']);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2), new NullLogger()))->process($auditContext);

        self::assertSame([['stage' => 'scan', 'file' => 'apps/api/Big.php', 'status' => 'skipped']], $auditContext->coverage());
    }

    /**
     * @throws InvalidAuditContextException
     */
    #[DataProvider('spellingsOfTheSameDirectory')]
    public function test_a_path_spelled_with_dot_or_empty_segments_records_the_same_skipped_files(string $path): void
    {
        mkdir($this->tmpDir.'/src/Admin', 0o777, true);
        mkdir($this->tmpDir.'/src/Billing', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Admin/Big.php', str_repeat('a', (2 * 1024) + 1));
        file_put_contents($this->tmpDir.'/src/Admin/Small.php', '<?php');
        file_put_contents($this->tmpDir.'/src/Billing/Big.php', str_repeat('a', (2 * 1024) + 1));

        $auditContext = AuditContext::forProject($this->tmpDir, [$path]);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2), new NullLogger()))->process($auditContext);

        $auditReport = AuditReport::fromContext($auditContext);
        self::assertSame([['stage' => 'scan', 'file' => 'src/Admin/Big.php', 'status' => 'skipped']], $auditContext->coverage());
        self::assertSame(['src/Admin/Small.php'], $this->analyzedPaths($auditContext));
        self::assertSame([], $auditReport->unanalyzedFiles());
        self::assertTrue($auditReport->isComplete());
    }

    /** @return iterable<string, array{string}> */
    public static function spellingsOfTheSameDirectory(): iterable
    {
        yield 'the plain spelling' => ['src/Admin'];
        yield 'a parent segment' => ['src/Billing/../Admin'];
        yield 'a current directory segment' => ['src/./Admin'];
        yield 'an empty segment' => ['src//Admin'];
        yield 'a leading current directory and a trailing separator' => ['./src/./Admin//'];
        yield 'backslashes and a parent segment' => ['src\\Billing\\..\\Admin'];
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_blank_path_is_no_path_and_leaves_the_configured_scan_surface_alone(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        mkdir($this->tmpDir.'/apps/api', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Big.php', str_repeat('a', (2 * 1024) + 1));
        file_put_contents($this->tmpDir.'/apps/api/Big.php', str_repeat('a', (2 * 1024) + 1));

        $auditContext = AuditContext::forProject($this->tmpDir, ['', ' ']);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2), new NullLogger()))->process($auditContext);

        self::assertSame([['stage' => 'scan', 'file' => 'src/Big.php', 'status' => 'skipped']], $auditContext->coverage());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_only_a_file_over_the_size_limit_changed_since_the_ref_is_recorded(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/ChangedBig.php', str_repeat('a', (2 * 1024) + 1));
        file_put_contents($this->tmpDir.'/src/UnchangedBig.php', str_repeat('a', (2 * 1024) + 1));
        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['src/ChangedBig.php']);

        $auditContext = AuditContext::forProject($this->tmpDir, diffSinceRef: 'origin/main');
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2), new NullLogger(), $gitChangedFilesResolver))->process($auditContext);

        self::assertSame([['stage' => 'scan', 'file' => 'src/ChangedBig.php', 'status' => 'skipped']], $auditContext->coverage());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_the_warning_names_each_skipped_file_and_why(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Big.php', str_repeat('a', (2 * 1024) + 1));
        file_put_contents($this->tmpDir.'/src/Unreadable.php', '<?php');
        $reader = static function (SplFileInfo $splFile): string {
            if (str_ends_with($splFile->getPathname(), 'Unreadable.php')) {
                throw new RuntimeException('disk read error');
            }

            return $splFile->getContents();
        };

        $bufferingLogger = new BufferingLogger();
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 2, fileReader: $reader), $bufferingLogger))->process(AuditContext::forProject($this->tmpDir));

        $message = 'The scan left a file out, so it is not analyzed';
        $logs = $bufferingLogger->cleanLogs();
        self::assertContains(['warning', $message, ['file' => 'src/Big.php', 'reason' => 'it is larger than the scan size limit (scan.max_file_size_kb)']], $logs);
        self::assertContains(['warning', $message, ['file' => 'src/Unreadable.php', 'reason' => 'it could not be read']], $logs);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_scanner_that_does_not_report_skipped_files_records_none(): void
    {
        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $scanner->method('scan')->willReturn([ProjectFile::create('src/A.php', $this->tmpDir.'/src/A.php', '<?php')]);

        $auditContext = AuditContext::forProject($this->tmpDir);
        (new IngestionStage($scanner, new NullLogger()))->process($auditContext);

        self::assertSame([], $auditContext->coverage());
        self::assertSame(['src/A.php'], $this->analyzedPaths($auditContext));
    }

    /**
     * @return list<string>
     */
    private function analyzedPaths(AuditContext $auditContext): array
    {
        return array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $auditContext->projectFiles());
    }

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/ingestion_skipped_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }
}
