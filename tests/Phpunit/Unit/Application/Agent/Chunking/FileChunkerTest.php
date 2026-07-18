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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\ChunkingStrategy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

final class FileChunkerTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('projectFileTypeCases')]
    public function test_type_strategy_orders_every_known_type_before_an_unrecognized_file(string $path, string $content): void
    {
        $files = [
            $this->makeFile('README.md'),
            ProjectFile::create($path, '/app/'.$path, $content),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Type, 10))->chunk($files);

        self::assertSame($path, $chunks[0][0]->relativePath());
    }

    /** @return iterable<string, array{string, string}> */
    public static function projectFileTypeCases(): iterable
    {
        yield 'controller' => ['src/Controller/UserController.php', '<?php'];
        yield 'api resource' => ['src/ApiResource/Offer.php', "<?php\n#[ApiResource]\nclass Offer {}"];
        yield 'live component' => ['src/Twig/Components/SearchBar.php', "<?php\n#[AsLiveComponent]\nclass SearchBar {}"];
        yield 'entity' => ['src/Entity/User.php', '<?php'];
        yield 'voter' => ['src/Security/UserVoter.php', '<?php'];
        yield 'repository' => ['src/Repository/UserRepository.php', '<?php'];
        yield 'form' => ['src/Form/UserType.php', '<?php'];
        yield 'authenticator' => ['src/Security/LoginFormAuthenticator.php', '<?php'];
        yield 'ldap service' => ['src/Ldap/DirectoryLookup.php', '<?php'];
        yield 'sonata admin' => ['src/Admin/StoreManager.php', '<?php'];
        yield 'messenger handler' => ['src/Messenger/SendInvoiceMessageHandler.php', '<?php'];
        yield 'webhook consumer' => ['src/Webhook/StripeWebhookConsumer.php', '<?php'];
        yield 'event subscriber' => ['src/EventSubscriber/AuditSubscriber.php', '<?php'];
        yield 'normalizer' => ['src/Serializer/UserNormalizer.php', '<?php'];
        yield 'scheduler' => ['src/Schedule/CleanupSchedule.php', '<?php'];
        yield 'template' => ['templates/user/index.html.twig', '{{ user.name }}'];
        yield 'config' => ['config/security.yaml', 'security:'];
        yield 'plain php' => ['src/Service/FooService.php', '<?php'];
    }

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
    public function test_feature_strategy_groups_an_api_resource_with_its_repository(): void
    {
        $files = [
            $this->makeFileWithContent('src/ApiResource/Offer.php', "<?php\n#[ApiResource]\nclass Offer {}"),
            $this->makeFile('src/Repository/OfferRepository.php'),
            $this->makeFile('src/Entity/Order.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $offerChunk = $this->findChunkContaining($chunks, 'src/ApiResource/Offer.php');
        self::assertNotNull($offerChunk);
        $offerChunkPaths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $offerChunk);
        self::assertContains('src/Repository/OfferRepository.php', $offerChunkPaths);
        self::assertNotContains('src/Entity/Order.php', $offerChunkPaths);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_feature_strategy_groups_an_easyadmin_crud_controller_with_its_repository(): void
    {
        $files = [
            $this->makeFileWithContent('src/Controller/Admin/ProductCrudController.php', "<?php\nclass ProductCrudController extends AbstractCrudController {}"),
            $this->makeFile('src/Repository/ProductRepository.php'),
            $this->makeFile('src/Entity/Order.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $productChunk = $this->findChunkContaining($chunks, 'src/Controller/Admin/ProductCrudController.php');
        self::assertNotNull($productChunk);
        $productChunkPaths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $productChunk);
        self::assertContains('src/Repository/ProductRepository.php', $productChunkPaths);
        self::assertNotContains('src/Entity/Order.php', $productChunkPaths);
        self::assertSame('src/Controller/Admin/ProductCrudController.php', $productChunk[0]->relativePath());
    }

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
    public function test_feature_matches_a_camel_case_boundary_starting_with_a_non_ascii_uppercase_letter(): void
    {
        $files = [
            $this->makeFile('src/Controller/EleveController.php'),
            $this->makeFile('src/Entity/EleveÉcole.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $eleveChunk = $this->findChunkContaining($chunks, 'src/Controller/EleveController.php');
        self::assertNotNull($eleveChunk);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $eleveChunk);
        self::assertContains('src/Entity/EleveÉcole.php', $paths);
    }

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
    public function test_feature_strategy_keeps_prefix_colliding_controllers_in_separate_chunks(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Controller/UsersController.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        $usersChunk = $this->findChunkContaining($chunks, 'src/Controller/UsersController.php');
        self::assertNotNull($userChunk);
        self::assertNotNull($usersChunk);
        $userChunkPaths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $userChunk);
        self::assertNotContains('src/Controller/UsersController.php', $userChunkPaths);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_feature_strategy_prefers_the_longer_more_specific_feature_for_a_prefix_overlapping_controller(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Controller/UserAddressController.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        $userAddressChunk = $this->findChunkContaining($chunks, 'src/Controller/UserAddressController.php');
        self::assertNotNull($userChunk);
        self::assertNotNull($userAddressChunk);
        $userChunkPaths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $userChunk);
        self::assertNotContains('src/Controller/UserAddressController.php', $userChunkPaths);
        self::assertCount(2, $chunks);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_feature_strategy_leaves_a_feature_with_no_chunk_when_a_longer_feature_claims_its_only_file_via_a_directory_match(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserSettings/UserController.php'),
            $this->makeFile('src/Controller/UserSettingsController.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        self::assertCount(1, $chunks);
        $paths = $this->allPaths($chunks);
        self::assertContains('src/Controller/UserSettings/UserController.php', $paths);
        self::assertContains('src/Controller/UserSettingsController.php', $paths);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_feature_strategy_still_chunks_every_later_feature_after_a_feature_emptied_by_a_directory_claim(): void
    {
        $files = [
            $this->makeFile('src/Controller/Order/UserController.php'),
            $this->makeFile('src/Controller/OrderController.php'),
            $this->makeFile('src/Controller/ProductController.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        self::assertCount(2, $chunks);
        $productChunk = $this->findChunkContaining($chunks, 'src/Controller/ProductController.php');
        self::assertNotNull($productChunk);
        self::assertCount(1, $productChunk);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_feature_strategy_chunks_later_features_correctly_alongside_prefix_colliding_ones(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Controller/UsersController.php'),
            $this->makeFile('src/Controller/OrderController.php'),
            $this->makeFile('src/Entity/Order.php'),
            $this->makeFile('src/Service/Misc.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $orderChunk = $this->findChunkContaining($chunks, 'src/Controller/OrderController.php');
        self::assertNotNull($orderChunk);
        $orderChunkPaths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $orderChunk);
        self::assertContains('src/Entity/Order.php', $orderChunkPaths);
        self::assertNotContains('src/Service/Misc.php', $orderChunkPaths);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_feature_keeps_a_file_matching_two_equal_length_features_with_the_first_matched_feature(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/Controller/PostController.php'),
            $this->makeFile('src/User/Post/Shared.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        self::assertNotNull($userChunk);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $userChunk);
        self::assertContains('src/User/Post/Shared.php', $paths);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_feature_does_not_group_a_file_whose_remainder_after_the_feature_starts_with_a_digit(): void
    {
        $files = [
            $this->makeFile('src/Controller/UserController.php'),
            $this->makeFile('src/User2Repository.php'),
        ];

        $chunks = (new FileChunker(ChunkingStrategy::Feature, 10))->chunk($files);

        $userChunk = $this->findChunkContaining($chunks, 'src/Controller/UserController.php');
        self::assertNotNull($userChunk);
        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $userChunk);
        self::assertNotContains('src/User2Repository.php', $paths);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_non_positive_chunk_size_is_clamped_to_one(): void
    {
        $files = [$this->makeFile('src/A.php'), $this->makeFile('src/B.php')];

        $chunks = (new FileChunker(ChunkingStrategy::Type, 0))->chunk($files);

        self::assertCount(2, $chunks);
        self::assertCount(1, $chunks[0]);
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFileWithContent(string $path, string $content): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, $content);
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
