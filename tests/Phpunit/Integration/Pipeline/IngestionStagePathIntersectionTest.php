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
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;

final class IngestionStagePathIntersectionTest extends TestCase
{
    private string $tmpDir;

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_path_wider_than_the_configured_scope_audits_only_the_part_of_it_the_scope_reaches(): void
    {
        $auditContext = $this->ingest(['src/Controller'], ['src']);

        self::assertSame(['src/Controller/A.php'], $this->relativePaths($auditContext->projectFiles()));
        self::assertSame(1, AuditReport::fromContext($auditContext)->filesDiscovered());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_path_inside_the_configured_scope_audits_the_files_under_it(): void
    {
        $auditContext = $this->ingest(['src', 'config'], ['src/Controller']);

        self::assertSame(['src/Controller/A.php'], $this->relativePaths($auditContext->projectFiles()));
        self::assertSame(['config/packages/security.yaml', 'src/Controller/A.php', 'src/Service/B.php'], $this->relativePaths($auditContext->mappingFiles()));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_path_that_names_one_file_of_the_configured_scope_audits_that_file(): void
    {
        $auditContext = $this->ingest(['src'], ['src/Service/B.php']);

        self::assertSame(['src/Service/B.php'], $this->relativePaths($auditContext->projectFiles()));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_when_one_of_several_paths_meets_the_configured_scope_the_others_add_nothing(): void
    {
        $auditContext = $this->ingest(['src'], ['src/Controller', 'apps/api']);

        self::assertSame(['src/Controller/A.php'], $this->relativePaths($auditContext->projectFiles()));
        self::assertSame(['src/Controller/A.php', 'src/Service/B.php'], $this->relativePaths($auditContext->mappingFiles()));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_path_the_configured_scope_does_not_reach_is_scanned_itself(): void
    {
        $auditContext = $this->ingest(['src'], ['apps/api']);

        self::assertSame(['apps/api/src/ApiController.php'], $this->relativePaths($auditContext->projectFiles()));
        self::assertSame(1, AuditReport::fromContext($auditContext)->filesDiscovered());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_path_the_configured_scope_does_not_reach_still_leaves_the_scope_in_the_mapping(): void
    {
        $auditContext = $this->ingest(['src', 'config'], ['apps/api']);

        self::assertSame(
            ['config/packages/security.yaml', 'src/Controller/A.php', 'src/Service/B.php', 'apps/api/src/ApiController.php'],
            $this->relativePaths($auditContext->mappingFiles()),
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_path_that_exists_nowhere_audits_no_file(): void
    {
        $auditContext = $this->ingest(['src'], ['apps/missing']);

        self::assertSame([], $auditContext->projectFiles());
        self::assertSame(0, AuditReport::fromContext($auditContext)->filesDiscovered());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_file_the_scan_left_out_is_recorded_only_when_the_run_was_asked_to_cover_it(): void
    {
        $oversize = '<?php // '.str_repeat('x', 2048);
        (new Filesystem())->dumpFile($this->tmpDir.'/src/Controller/Big.php', $oversize);
        (new Filesystem())->dumpFile($this->tmpDir.'/src/Service/Big.php', $oversize);

        $auditContext = $this->ingest(['src/Controller'], ['src/Service', 'src/Controller'], 1);

        self::assertSame([['stage' => 'scan', 'file' => 'src/Controller/Big.php', 'status' => 'errored']], $auditContext->coverage());
        self::assertSame(['src/Controller/A.php'], $this->relativePaths($auditContext->projectFiles()));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_file_left_out_of_a_path_the_configured_scope_does_not_reach_is_recorded(): void
    {
        (new Filesystem())->dumpFile($this->tmpDir.'/apps/api/src/Big.php', '<?php // '.str_repeat('x', 2048));

        $auditContext = $this->ingest(['src'], ['apps/api'], 1);

        self::assertSame([['stage' => 'scan', 'file' => 'apps/api/src/Big.php', 'status' => 'errored']], $auditContext->coverage());
        self::assertSame(['apps/api/src/ApiController.php'], $this->relativePaths($auditContext->projectFiles()));
    }

    /**
     * @param list<string> $includedPaths
     * @param list<string> $scanPaths
     *
     * @throws InvalidAuditContextException
     */
    private function ingest(array $includedPaths, array $scanPaths, int $maxFileSizeKb = ProjectFileScanner::DEFAULT_MAX_FILE_SIZE_KB): AuditContext
    {
        $auditContext = AuditContext::forProject($this->tmpDir, $scanPaths);
        (new IngestionStage(new ProjectFileScanner(new NullLogger(), $includedPaths, maxFileSizeKb: $maxFileSizeKb), new NullLogger()))->process($auditContext);

        return $auditContext;
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

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/ingestion_path_intersection_'.uniqid('', true);
        $filesystem = new Filesystem();
        $filesystem->dumpFile($this->tmpDir.'/config/packages/security.yaml', 'security: {}');
        $filesystem->dumpFile($this->tmpDir.'/src/Controller/A.php', '<?php class A {}');
        $filesystem->dumpFile($this->tmpDir.'/src/Service/B.php', '<?php class B {}');
        $filesystem->dumpFile($this->tmpDir.'/apps/api/src/ApiController.php', '<?php class ApiController {}');
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmpDir);
    }
}
