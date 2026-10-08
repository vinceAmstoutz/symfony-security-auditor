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
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\ChunkingStrategy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerSkillPromptRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture\MappingSettingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture\RecordingAttackerPromptBuilder;

final class EstimateAuditCostUseCasePromptOverheadTest extends TestCase
{
    private const string SYSTEM_PROMPT = 'SYSTEM-PROMPT';

    private const string MAPPING_MESSAGE = 'MAPPING-MESSAGE-OF-THE-PROJECT';

    private string $projectDir;

    #[Override]
    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir().'/estimate_overhead_'.uniqid('', true);
        mkdir($this->projectDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectDir);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_each_chunk_carries_the_whole_system_prompt_in_place_of_the_skill_blocks(): void
    {
        $estimateAuditCostUseCase = $this->useCase(
            [$this->file('a.php', 'aaa'), $this->file('b.php', 'bbb')],
            attackerPromptBuilder: new RecordingAttackerPromptBuilder(self::SYSTEM_PROMPT, ''),
        );

        $inputTokens = $estimateAuditCostUseCase->execute($this->projectDir)->cost()->byRole()['attacker']['input_tokens'];

        self::assertSame(3 + 3 + (2 * \strlen(self::SYSTEM_PROMPT)), $inputTokens);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_the_system_prompt_is_built_for_each_chunks_own_files(): void
    {
        $recordingAttackerPromptBuilder = new RecordingAttackerPromptBuilder(self::SYSTEM_PROMPT, '');

        $this->useCase([$this->file('a.php', 'aaa'), $this->file('b.php', 'bbb')], attackerPromptBuilder: $recordingAttackerPromptBuilder)->execute($this->projectDir);

        self::assertSame([['a.php'], ['b.php']], $recordingAttackerPromptBuilder->systemPromptFiles);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_each_chunk_carries_the_project_mapping(): void
    {
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());
        $recordingAttackerPromptBuilder = new RecordingAttackerPromptBuilder(self::SYSTEM_PROMPT, self::MAPPING_MESSAGE);
        $estimateAuditCostUseCase = $this->useCase(
            [$this->file('a.php', 'aaa'), $this->file('b.php', 'bbb')],
            attackerPromptBuilder: $recordingAttackerPromptBuilder,
            mappingStage: new MappingSettingStage($symfonyMapping),
        );

        $inputTokens = $estimateAuditCostUseCase->execute($this->projectDir)->cost()->byRole()['attacker']['input_tokens'];

        self::assertSame(3 + 3 + (2 * (\strlen(self::SYSTEM_PROMPT) + \strlen(self::MAPPING_MESSAGE))), $inputTokens);
        self::assertSame([[]], $recordingAttackerPromptBuilder->userMessageFiles);
        self::assertSame([$symfonyMapping], $recordingAttackerPromptBuilder->userMessageMappings);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_the_mapping_is_built_from_the_scanned_files_the_git_diff_has_not_narrowed(): void
    {
        $mappingSettingStage = new MappingSettingStage(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));
        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['a.php']);
        $estimateAuditCostUseCase = $this->useCase(
            [$this->file('a.php', 'aaa'), $this->file('b.php', 'bbb')],
            attackerPromptBuilder: new RecordingAttackerPromptBuilder(self::SYSTEM_PROMPT, self::MAPPING_MESSAGE),
            mappingStage: $mappingSettingStage,
            gitChangedFilesResolver: $gitChangedFilesResolver,
        );

        $inputTokens = $estimateAuditCostUseCase->execute($this->projectDir, diffSinceRef: 'main')->cost()->byRole()['attacker']['input_tokens'];

        self::assertSame([['a.php', 'b.php']], $mappingSettingStage->mappedFiles);
        self::assertSame(3 + \strlen(self::SYSTEM_PROMPT) + \strlen(self::MAPPING_MESSAGE), $inputTokens);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_a_mapping_stage_with_no_prompt_builder_adds_nothing(): void
    {
        $mappingSettingStage = new MappingSettingStage(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));
        $estimateAuditCostUseCase = $this->useCase([$this->file('a.php', 'aaa')], mappingStage: $mappingSettingStage);

        $inputTokens = $estimateAuditCostUseCase->execute($this->projectDir)->cost()->byRole()['attacker']['input_tokens'];

        self::assertSame(3 + \strlen('SKILLS'), $inputTokens);
        self::assertSame([], $mappingSettingStage->mappedFiles);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_a_prompt_builder_with_no_mapping_stage_adds_no_mapping(): void
    {
        $recordingAttackerPromptBuilder = new RecordingAttackerPromptBuilder(self::SYSTEM_PROMPT, self::MAPPING_MESSAGE);
        $estimateAuditCostUseCase = $this->useCase([$this->file('a.php', 'aaa')], attackerPromptBuilder: $recordingAttackerPromptBuilder);

        $inputTokens = $estimateAuditCostUseCase->execute($this->projectDir)->cost()->byRole()['attacker']['input_tokens'];

        self::assertSame(3 + \strlen(self::SYSTEM_PROMPT), $inputTokens);
        self::assertSame([], $recordingAttackerPromptBuilder->userMessageFiles);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_a_mapping_stage_that_maps_nothing_adds_no_mapping(): void
    {
        $estimateAuditCostUseCase = $this->useCase(
            [$this->file('a.php', 'aaa')],
            attackerPromptBuilder: new RecordingAttackerPromptBuilder(self::SYSTEM_PROMPT, self::MAPPING_MESSAGE),
            mappingStage: new MappingSettingStage(null),
        );

        $inputTokens = $estimateAuditCostUseCase->execute($this->projectDir)->cost()->byRole()['attacker']['input_tokens'];

        self::assertSame(3 + \strlen(self::SYSTEM_PROMPT), $inputTokens);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_the_tool_round_trips_and_the_iterations_scale_the_prompt_overhead_with_the_files(): void
    {
        $estimateAuditCostUseCase = $this->useCase(
            [$this->file('a.php', 'aaa')],
            attackerPromptBuilder: new RecordingAttackerPromptBuilder(self::SYSTEM_PROMPT, self::MAPPING_MESSAGE),
            mappingStage: new MappingSettingStage(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())),
            withToolRoundTrips: true,
        );

        $inputTokens = $estimateAuditCostUseCase->execute($this->projectDir)->cost()->byRole()['attacker']['input_tokens'];

        $perRound = 3 + \strlen(self::SYSTEM_PROMPT) + \strlen(self::MAPPING_MESSAGE);
        self::assertSame(2 * (int) ceil($perRound * (1.0 + EstimateAuditCostUseCase::DEFAULT_TOOL_ROUND_TRIP_RATIO)), $inputTokens);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_the_prompt_overhead_never_reaches_the_reviewer_estimate(): void
    {
        $withOverhead = $this->useCase(
            [$this->file('a.php', 'aaa')],
            attackerPromptBuilder: new RecordingAttackerPromptBuilder(self::SYSTEM_PROMPT, self::MAPPING_MESSAGE),
            mappingStage: new MappingSettingStage(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())),
        )->execute($this->projectDir)->cost()->byRole()['reviewer']['input_tokens'];
        $withoutOverhead = $this->useCase([$this->file('a.php', 'aaa')])->execute($this->projectDir)->cost()->byRole()['reviewer']['input_tokens'];

        self::assertSame($withoutOverhead, $withOverhead);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    public function test_a_project_with_no_files_has_no_chunk_to_carry_the_prompt_overhead(): void
    {
        $estimateAuditCostUseCase = $this->useCase(
            [],
            attackerPromptBuilder: new RecordingAttackerPromptBuilder(self::SYSTEM_PROMPT, self::MAPPING_MESSAGE),
            mappingStage: new MappingSettingStage(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())),
        );

        self::assertSame(0, $estimateAuditCostUseCase->execute($this->projectDir)->cost()->byRole()['attacker']['input_tokens']);
    }

    /**
     * @param list<ProjectFile> $files
     */
    private function useCase(
        array $files,
        ?AttackerPromptBuilderInterface $attackerPromptBuilder = null,
        ?StageInterface $mappingStage = null,
        ?GitChangedFilesResolverInterface $gitChangedFilesResolver = null,
        bool $withToolRoundTrips = false,
    ): EstimateAuditCostUseCase {
        return new EstimateAuditCostUseCase(
            $this->scanner($files),
            $this->lengthEchoingEstimator(),
            new CostCalculator($this->zeroPricing()),
            new NullLogger(),
            new FileChunker(ChunkingStrategy::Type, chunkSize: 1),
            $this->skillPromptRenderer('SKILLS'),
            'gpt-4o',
            $withToolRoundTrips ? 2 : 1,
            gitChangedFilesResolver: $gitChangedFilesResolver,
            toolsEnabled: $withToolRoundTrips,
            attackerPromptBuilder: $attackerPromptBuilder,
            mappingStage: $mappingStage,
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function file(string $relativePath, string $content): ProjectFile
    {
        return ProjectFile::create($relativePath, '/project/'.$relativePath, $content);
    }

    /**
     * @param list<ProjectFile> $files
     */
    private function scanner(array $files): ProjectFileScannerInterface
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

    private function skillPromptRenderer(string $skillPrompt): AttackerSkillPromptRendererInterface
    {
        $attackerSkillPromptRenderer = self::createStub(AttackerSkillPromptRendererInterface::class);
        $attackerSkillPromptRenderer->method('render')->willReturn($skillPrompt);

        return $attackerSkillPromptRenderer;
    }

    private function lengthEchoingEstimator(): TokenEstimatorInterface
    {
        return new class implements TokenEstimatorInterface {
            #[Override]
            public function estimateTokens(string $text, string $model): int
            {
                return mb_strlen($text);
            }
        };
    }

    private function zeroPricing(): PricingProviderInterface
    {
        return new class implements PricingProviderInterface {
            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }
        };
    }
}
