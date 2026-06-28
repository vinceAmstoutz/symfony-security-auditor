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
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;

final class ListScannedFilesUseCaseTest extends TestCase
{
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

    private function makeProjectFile(string $relativePath): ProjectFile
    {
        return ProjectFile::create($relativePath, '/project/'.$relativePath, '<?php');
    }
}
