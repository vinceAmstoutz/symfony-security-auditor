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

final class ProjectFileScannerScanWithinTest extends TestCase
{
    private Filesystem $filesystem;

    private string $project;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->project = sys_get_temp_dir().'/scanner_within_'.bin2hex(random_bytes(6));
        $this->filesystem->mkdir($this->project);
        $this->put('src/RootThing.php');
        $this->put('config/security.yaml', 'security: {}');
        $this->put('apps/api/src/ApiController.php');
        $this->put('apps/api/config/services.yaml', 'services: {}');
        $this->put('apps/web/src/WebController.php');
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove([$this->project, $this->project.'-outside']);
    }

    public function test_it_scans_a_directory_the_configured_paths_do_not_reach(): void
    {
        $files = (new ProjectFileScanner(new NullLogger()))->scanWithin($this->project, ['apps/api']);

        self::assertSame(['apps/api/config/services.yaml', 'apps/api/src/ApiController.php'], $this->relativePaths($files));
    }

    public function test_it_scans_the_given_paths_instead_of_the_configured_ones(): void
    {
        $files = (new ProjectFileScanner(new NullLogger(), ['src', 'config']))->scanWithin($this->project, ['apps/web']);

        self::assertSame(['apps/web/src/WebController.php'], $this->relativePaths($files));
    }

    public function test_it_scans_several_paths_and_single_files_in_relative_path_order(): void
    {
        $files = (new ProjectFileScanner(new NullLogger()))->scanWithin($this->project, ['apps/web', 'config/security.yaml', 'apps/api/src']);

        self::assertSame(['apps/api/src/ApiController.php', 'apps/web/src/WebController.php', 'config/security.yaml'], $this->relativePaths($files));
    }

    public function test_overlapping_paths_list_each_file_once(): void
    {
        $files = (new ProjectFileScanner(new NullLogger()))->scanWithin($this->project, ['apps/api', 'apps/api/src', 'apps/api/src/ApiController.php', 'apps/api']);

        self::assertSame(['apps/api/config/services.yaml', 'apps/api/src/ApiController.php'], $this->relativePaths($files));
    }

    public function test_it_keeps_the_extension_filter_inside_a_directory(): void
    {
        $this->put('apps/api/src/notes.txt', 'not code');
        $this->put('apps/api/src/app.js', 'console.log(1)');

        $files = (new ProjectFileScanner(new NullLogger()))->scanWithin($this->project, ['apps/api/src']);

        self::assertSame(['apps/api/src/ApiController.php'], $this->relativePaths($files));
    }

    public function test_it_keeps_the_size_limit(): void
    {
        $this->put('apps/api/src/Big.php', '<?php // '.str_repeat('x', 3000));

        $files = (new ProjectFileScanner(new NullLogger(), maxFileSizeKb: 1))->scanWithin($this->project, ['apps/api/src']);

        self::assertSame(['apps/api/src/ApiController.php'], $this->relativePaths($files));
    }

    public function test_it_keeps_respecting_gitignore_when_asked_to(): void
    {
        $this->put('apps/api/src/.gitignore', "Generated.php\n");
        $this->put('apps/api/src/Generated.php');

        $files = (new ProjectFileScanner(new NullLogger(), respectGitignore: true))->scanWithin($this->project, ['apps/api/src']);

        self::assertSame(['apps/api/src/ApiController.php'], $this->relativePaths($files));
    }

    public function test_a_path_that_does_not_exist_scans_nothing_and_says_which_paths_were_asked_for(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(static function (string $message, array $context = []) use (&$warnings): void {
            $warnings[] = [$message, $context];
        });

        $files = (new ProjectFileScanner($logger))->scanWithin($this->project, ['apps/missing']);

        self::assertSame([], $files);
        self::assertSame([['No scan paths exist in project', ['scan_paths' => ['apps/missing'], 'project_path' => $this->project]]], $warnings);
    }

    public function test_a_path_that_climbs_out_of_the_project_is_skipped_and_logged(): void
    {
        $this->put('../'.basename($this->project).'-outside/Secret.php');
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(static function (string $message, array $context = []) use (&$warnings): void {
            $warnings[] = $message;
        });

        $files = (new ProjectFileScanner($logger))->scanWithin($this->project, ['apps/api/src', '../'.basename($this->project).'-outside']);

        self::assertSame(['apps/api/src/ApiController.php'], $this->relativePaths($files));
        self::assertSame(['Skipped included path outside the project root'], $warnings);
    }

    public function test_a_symlinked_path_is_skipped_and_logged(): void
    {
        $this->filesystem->symlink($this->project.'/apps/api', $this->project.'/linked');
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(static function (string $message, array $context = []) use (&$warnings): void {
            $warnings[] = $message;
        });

        $files = (new ProjectFileScanner($logger))->scanWithin($this->project, ['linked']);

        self::assertSame([], $files);
        self::assertContains('Skipped symlinked included path', $warnings);
    }

    public function test_scanning_without_given_paths_still_uses_the_configured_ones(): void
    {
        $files = (new ProjectFileScanner(new NullLogger(), ['src']))->scan($this->project);

        self::assertSame(['src/RootThing.php'], $this->relativePaths($files));
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
