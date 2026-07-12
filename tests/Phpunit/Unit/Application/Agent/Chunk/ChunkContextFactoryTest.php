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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;

final class ChunkContextFactoryTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_derives_a_different_cache_key_when_risk_markers_differ_for_an_otherwise_identical_chunk(): void
    {
        $chunkContextFactory = new ChunkContextFactory(
            self::createStub(AttackerPromptBuilderInterface::class),
            new NullCodeSlicer(),
            new AttackerContextPromptRenderer(),
        );

        $projectFile = ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php class A {}');
        $chunk = [$projectFile];
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());
        $attackerAnalysisRequest = new AttackerAnalysisRequest($chunk, $symfonyMapping);

        $chunkContext = $chunkContextFactory->create($chunk, $attackerAnalysisRequest, new RiskMarkerIndex([]), true);

        $riskMarker = RiskMarker::create($projectFile->relativePath(), 1, 'sql_injection', 'raw query concatenation');
        $withMarkers = $chunkContextFactory->create($chunk, $attackerAnalysisRequest, new RiskMarkerIndex([$riskMarker]), true);

        self::assertNotSame($chunkContext->contextKey, $withMarkers->contextKey);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_a_risk_marker_line_absent_from_the_sliced_output_is_not_restored(): void
    {
        $codeSlicer = self::createStub(CodeSlicerInterface::class);
        $codeSlicer->method('slice')->willReturn('<?php');

        $chunkContextFactory = new ChunkContextFactory(
            new AttackerPromptBuilder(),
            $codeSlicer,
            new AttackerContextPromptRenderer(),
        );

        $projectFile = ProjectFile::create('src/Repository/UserRepository.php', '/app/src/Repository/UserRepository.php', "<?php\n\$a = 1;\n\$b = 2;\nDANGER_LINE_HERE\n\$d = 4;");
        $chunk = [$projectFile];
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());
        $attackerAnalysisRequest = new AttackerAnalysisRequest($chunk, $symfonyMapping);

        $riskMarker = RiskMarker::create($projectFile->relativePath(), 4, 'sql_injection', 'raw query concatenation');
        $chunkContext = $chunkContextFactory->create($chunk, $attackerAnalysisRequest, new RiskMarkerIndex([$riskMarker]), true);

        self::assertStringNotContainsString('DANGER_LINE_HERE', $chunkContext->userMessage);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_file_without_risk_markers_keeps_the_slicer_output_verbatim(): void
    {
        $codeSlicer = self::createStub(CodeSlicerInterface::class);
        $codeSlicer->method('slice')->willReturn("<?php\n// SLICED_ONLY_TOKEN");

        $chunkContextFactory = new ChunkContextFactory(
            new AttackerPromptBuilder(),
            $codeSlicer,
            new AttackerContextPromptRenderer(),
        );

        $projectFile = ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', "<?php\nORIGINAL_ONLY_TOKEN\n// more");
        $chunk = [$projectFile];
        $attackerAnalysisRequest = new AttackerAnalysisRequest($chunk, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        $chunkContext = $chunkContextFactory->create($chunk, $attackerAnalysisRequest, new RiskMarkerIndex([]), true);

        self::assertStringContainsString('SLICED_ONLY_TOKEN', $chunkContext->userMessage);
    }
}
