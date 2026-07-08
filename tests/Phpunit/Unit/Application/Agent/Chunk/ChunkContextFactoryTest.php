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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;

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
}
