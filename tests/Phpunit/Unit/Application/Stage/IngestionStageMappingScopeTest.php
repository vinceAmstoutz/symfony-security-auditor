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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Stage;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Scan\Fixture\RecordingScopedScanner;

final class IngestionStageMappingScopeTest extends TestCase
{
    private string $tmpDir;

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_a_path_narrows_the_audited_files_and_not_the_files_the_mapping_is_built_from(): void
    {
        $recordingScopedScanner = new RecordingScopedScanner(
            [
                $this->file('config/packages/security.yaml'),
                $this->file('src/Controller/AdminController.php'),
                $this->file('src/Security/PostVoter.php'),
            ],
            [$this->file('src/Controller/AdminController.php')],
        );
        $auditContext = AuditContext::forProject($this->tmpDir, ['src/Controller']);

        (new IngestionStage($recordingScopedScanner, new NullLogger()))->process($auditContext);

        self::assertSame(['src/Controller/AdminController.php'], $this->relativePaths($auditContext->projectFiles()));
        self::assertSame(
            ['config/packages/security.yaml', 'src/Controller/AdminController.php', 'src/Security/PostVoter.php'],
            $this->relativePaths($auditContext->mappingFiles()),
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_a_path_that_matches_no_file_still_reports_that_the_scan_found_none(): void
    {
        $recordingScopedScanner = new RecordingScopedScanner([$this->file('src/Controller/A.php')], []);
        $auditContext = AuditContext::forProject($this->tmpDir, ['src/Typo']);

        (new IngestionStage($recordingScopedScanner, new NullLogger()))->process($auditContext);

        self::assertSame(0, AuditReport::fromContext($auditContext)->filesDiscovered());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_a_path_and_a_since_ref_narrow_the_audited_files_while_the_scan_scope_keeps_counting_as_discovered(): void
    {
        $recordingScopedScanner = new RecordingScopedScanner(
            [$this->file('src/Controller/A.php'), $this->file('src/Controller/B.php'), $this->file('src/Service/C.php')],
            [$this->file('src/Controller/A.php'), $this->file('src/Controller/B.php')],
        );
        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['src/Controller/A.php']);
        $auditContext = AuditContext::forProject($this->tmpDir, ['src/Controller'], false, 'main');

        (new IngestionStage($recordingScopedScanner, new NullLogger(), $gitChangedFilesResolver))->process($auditContext);

        $auditReport = AuditReport::fromContext($auditContext);
        self::assertSame(['src/Controller/A.php'], $this->relativePaths($auditContext->projectFiles()));
        self::assertSame(['src/Controller/A.php', 'src/Controller/B.php', 'src/Service/C.php'], $this->relativePaths($auditContext->mappingFiles()));
        self::assertSame(2, $auditReport->filesDiscovered());
        self::assertSame(1, $auditReport->filesScanned());
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/ingestion_mapping_scope_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmpDir);
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

    /**
     * @throws InvalidProjectFileException
     */
    private function file(string $relativePath): ProjectFile
    {
        return ProjectFile::create($relativePath, '/project/'.$relativePath, '<?php');
    }
}
