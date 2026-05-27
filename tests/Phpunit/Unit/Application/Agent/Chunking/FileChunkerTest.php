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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunking;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\ChunkingStrategy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

final class FileChunkerTest extends TestCase
{
    public function test_feature_strategy_groups_related_files_together(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Entity/User.php'),
            $this->makeFile('src/Repository/UserRepository.php'),
            $this->makeFile('src/Form/UserType.php'),
            $this->makeFile('src/Controller/OrderController.php'),
            $this->makeFile('src/Entity/Order.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        self::assertNotNull($userChunk);
        $userChunkPaths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $userChunk);
        self::assertContains('src/Entity/User.php', $userChunkPaths);
        self::assertContains('src/Repository/UserRepository.php', $userChunkPaths);
        self::assertContains('src/Form/UserType.php', $userChunkPaths);
        self::assertNotContains('src/Entity/Order.php', $userChunkPaths);
    }

    public function test_feature_strategy_groups_templates_under_matching_directory(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('templates/user/index.html.twig'),
            $this->makeFile('templates/user/edit.html.twig'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        self::assertNotNull($userChunk);
        $userChunkPaths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $userChunk);
        self::assertContains('templates/user/index.html.twig', $userChunkPaths);
        self::assertContains('templates/user/edit.html.twig', $userChunkPaths);
    }

    public function test_feature_strategy_keeps_unrelated_files_in_leftover_chunks(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Service/SharedService.php'),
            $this->makeFile('config/services.yaml'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $allChunkedPaths = $this->allPaths($chunks);
        self::assertContains('src/Service/SharedService.php', $allChunkedPaths);
        self::assertContains('config/services.yaml', $allChunkedPaths);
    }

    public function test_feature_strategy_orders_files_within_chunk_by_attack_surface_priority(): void
    {
        $files = [
            $this->makeFile('src/Form/UserType.php'),
            $this->makeFile('src/Entity/User.php'),
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Repository/UserRepository.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        self::assertNotNull($userChunk);
        self::assertSame('src/Controller/UserController.php', $userChunk[0]->relativePath());
    }

    public function test_feature_strategy_returns_empty_array_when_no_files(): void
    {
        self::assertSame([], (new FileChunker(ChunkingStrategy::Feature))->chunk([]));
    }

    public function test_feature_strategy_returns_only_leftovers_when_no_controllers(): void
    {
        $files = [
            $this->makeFile('src/Service/Foo.php'),
            $this->makeFile('src/Service/Bar.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        self::assertCount(1, $chunks);
        self::assertCount(2, $chunks[0]);
    }

    public function test_feature_strategy_splits_oversized_feature_into_multiple_chunks(): void
    {
        $files = [$this->makeFile('src/Controller/UserController.php')];
        for ($i = 0; $i < 11; ++$i) {
            $files[] = $this->makeFile('templates/user/page'.$i.'.html.twig');
        }

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunks = array_values(array_filter($chunks, static function (array $chunk): bool {
            foreach ($chunk as $file) {
                if (str_contains($file->relativePath(), '/user/') || str_contains($file->relativePath(), 'UserController')) {
                    return true;
                }
            }

            return false;
        }));

        self::assertGreaterThan(1, \count($userChunks));
    }

    public function test_type_strategy_sorts_by_priority(): void
    {
        $files = [
            $this->makeFile('src/Service/FooService.php'),
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Entity/User.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Type, 10))->chunk($files);

        self::assertCount(1, $chunks);
        self::assertSame('src/Controller/UserController.php', $chunks[0][0]->relativePath());
    }

    public function test_type_strategy_chunks_in_fixed_size_windows(): void
    {
        $files = [];
        for ($i = 0; $i < 25; ++$i) {
            $files[] = $this->makeFile('src/Service/Foo'.$i.'.php');
        }

        $chunks = (new FileChunker(ChunkingStrategy::Type, 10))->chunk($files);

        self::assertCount(3, $chunks);
        self::assertCount(10, $chunks[0]);
        self::assertCount(10, $chunks[1]);
        self::assertCount(5, $chunks[2]);
    }

    public function test_default_strategy_is_feature(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Entity/User.php'),
        ];

        $chunks = (new FileChunker())->chunk($files);

        self::assertCount(1, $chunks);
        self::assertCount(2, $chunks[0]);
    }

    public function test_feature_extraction_skips_non_controllers_without_stopping(): void
    {
        $files = [
            $this->makeFile('src/Service/Foo.php'),
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Entity/User.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        self::assertNotNull($userChunk);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $userChunk);
        self::assertContains('src/Entity/User.php', $paths);
        self::assertNotContains('src/Service/Foo.php', $paths);
    }

    public function test_feature_assignment_continues_past_unrelated_files(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Service/Unrelated.php'),
            $this->makeFile('src/Entity/User.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        self::assertNotNull($userChunk);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $userChunk);
        self::assertContains('src/Entity/User.php', $paths);
        self::assertNotContains('src/Service/Unrelated.php', $paths);
    }

    public function test_feature_matches_files_whose_basename_starts_with_the_feature(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Entity/UserProfile.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        self::assertNotNull($userChunk);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $userChunk);
        self::assertContains('src/Entity/UserProfile.php', $paths);
    }

    public function test_feature_directory_match_requires_the_feature_segment_bounded_by_slashes(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/MyUser/Thing.php'),
            $this->makeFile('src/username/Other.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        self::assertNotNull($userChunk);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $userChunk);
        self::assertNotContains('src/MyUser/Thing.php', $paths);
        self::assertNotContains('src/username/Other.php', $paths);
    }

    public function test_each_feature_keeps_its_own_assignments(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Entity/User.php'),
            $this->makeFile('src/Controller/OrderController.php'),
            $this->makeFile('src/Entity/Order.php'),
            $this->makeFile('src/Service/Misc.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $orderChunk = $this->findChunkContaining($chunks, 'src/Controller/OrderController.php');
        self::assertNotNull($orderChunk);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $orderChunk);
        self::assertContains('src/Entity/Order.php', $paths);
        self::assertNotContains('src/Service/Misc.php', $paths);
    }

    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
    }

    /**
     * @param list<list<ProjectFile>> $chunks
     *
     * @return list<ProjectFile>|null
     */
    private function findChunkContaining(array $chunks, string $path): ?array
    {
        foreach ($chunks as $chunk) {
            foreach ($chunk as $file) {
                if ($file->relativePath() === $path) {
                    return $chunk;
                }
            }
        }

        return null;
    }

    /**
     * @param list<list<ProjectFile>> $chunks
     *
     * @return list<string>
     */
    private function allPaths(array $chunks): array
    {
        $paths = [];
        foreach ($chunks as $chunk) {
            foreach ($chunk as $file) {
                $paths[] = $file->relativePath();
            }
        }

        return $paths;
    }
}
