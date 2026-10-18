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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Scan\Fixture\RecordingScopedScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture\ProbingScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture\SinceClosureFixture;

final class ListScannedFilesUseCaseTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_returns_every_scanned_file_when_no_scan_paths_are_given(): void
    {
        $listScannedFilesUseCase = new ListScannedFilesUseCase($this->fixedScanner([
            $this->makeProjectFile('src/Controller/HomeController.php'),
            $this->makeProjectFile('config/packages/security.yaml'),
        ]));

        $files = $listScannedFilesUseCase->execute('/project');

        self::assertSame(
            ['src/Controller/HomeController.php', 'config/packages/security.yaml'],
            array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files),
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_lists_a_scan_path_the_configured_scan_does_not_reach_for_a_scanner_that_can_take_it(): void
    {
        $recordingScopedScanner = new RecordingScopedScanner(
            [$this->makeProjectFile('src/Configured.php')],
            [$this->makeProjectFile('apps/api/src/Outside.php')],
        );

        $files = (new ListScannedFilesUseCase($recordingScopedScanner))->execute('/project', ['apps/api']);

        self::assertSame(['apps/api/src/Outside.php'], array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files));
        self::assertSame([['scan', null], ['scanWithin', ['apps/api']]], $recordingScopedScanner->calls);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_lists_every_file_under_a_scan_path_the_configured_scan_reaches(): void
    {
        $recordingScopedScanner = new RecordingScopedScanner(
            [$this->makeProjectFile('src/Configured.php'), $this->makeProjectFile('config/services.yaml')],
            [$this->makeProjectFile('src/Configured.php'), $this->makeProjectFile('src/Unconfigured.php')],
        );

        $files = (new ListScannedFilesUseCase($recordingScopedScanner))->execute('/project', ['src']);

        self::assertSame(['src/Configured.php', 'src/Unconfigured.php'], array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files));
        self::assertSame([['scan', null], ['scanWithin', ['src']]], $recordingScopedScanner->calls);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_restricts_the_listing_to_the_given_scan_paths(): void
    {
        $listScannedFilesUseCase = new ListScannedFilesUseCase($this->fixedScanner([
            $this->makeProjectFile('apps/api/src/A.php'),
            $this->makeProjectFile('apps/web/src/B.php'),
        ]));

        $files = $listScannedFilesUseCase->execute('/project', ['apps/api']);

        self::assertSame(
            ['apps/api/src/A.php'],
            array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files),
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_diff_since_ref_narrows_the_listing_to_changed_files(): void
    {
        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['src/Changed.php']);

        $listScannedFilesUseCase = new ListScannedFilesUseCase(
            $this->fixedScanner([
                $this->makeProjectFile('src/Changed.php'),
                $this->makeProjectFile('src/Unchanged.php'),
            ]),
            $gitChangedFilesResolver,
        );

        $files = $listScannedFilesUseCase->execute('/project', [], 'main');

        self::assertSame(
            ['src/Changed.php'],
            array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files),
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_since_closure_lists_the_controllers_a_changed_voter_guards(): void
    {
        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['src/Security/PostVoter.php']);

        $listScannedFilesUseCase = new ListScannedFilesUseCase(
            $this->fixedScanner(SinceClosureFixture::files()),
            $gitChangedFilesResolver,
            SinceClosureFixture::preview('direct'),
        );

        $files = $listScannedFilesUseCase->execute(sys_get_temp_dir(), [], 'main');

        self::assertSame(
            ['src/Security/PostVoter.php', 'src/Controller/PostController.php'],
            array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files),
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_without_a_diff_since_ref_the_listing_covers_every_file(): void
    {
        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['src/Changed.php']);

        $listScannedFilesUseCase = new ListScannedFilesUseCase(
            $this->fixedScanner([
                $this->makeProjectFile('src/Changed.php'),
                $this->makeProjectFile('src/Unchanged.php'),
            ]),
            $gitChangedFilesResolver,
        );

        $files = $listScannedFilesUseCase->execute('/project');

        self::assertSame(
            ['src/Changed.php', 'src/Unchanged.php'],
            array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files),
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    #[DataProvider('probeAnswers')]
    public function test_a_scanner_that_can_probe_tells_whether_a_directory_holds_a_file_without_scanning_it(bool $reachesAFile): void
    {
        $probingScanner = new ProbingScanner($reachesAFile);

        $holdsAFile = (new ListScannedFilesUseCase($probingScanner))->holdsAFile('/project');

        self::assertSame([$reachesAFile, ['/project'], []], [$holdsAFile, $probingScanner->probedProjectPaths, $probingScanner->scannedProjectPaths]);
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function probeAnswers(): iterable
    {
        yield 'it reaches a file' => [true];
        yield 'it reaches none' => [false];
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_any_other_scanner_holds_a_file_when_its_scan_finds_one(): void
    {
        $listScannedFilesUseCase = new ListScannedFilesUseCase($this->fixedScanner([$this->makeProjectFile('lib/Legacy.php')]));

        self::assertTrue($listScannedFilesUseCase->holdsAFile('/project'));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_any_other_scanner_holds_no_file_when_its_scan_finds_none(): void
    {
        self::assertFalse((new ListScannedFilesUseCase($this->fixedScanner([])))->holdsAFile('/project'));
    }

    /**
     * @param list<ProjectFile> $files
     */
    private function fixedScanner(array $files): ProjectFileScannerInterface
    {
        return new class($files) implements ProjectFileScannerInterface {
            /** @param list<ProjectFile> $files */
            public function __construct(private readonly array $files) {}

            #[Override]
            public function scan(string $projectPath): array
            {
                return $this->files;
            }
        };
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeProjectFile(string $relativePath): ProjectFile
    {
        return ProjectFile::create($relativePath, '/project/'.$relativePath, '<?php');
    }
}
