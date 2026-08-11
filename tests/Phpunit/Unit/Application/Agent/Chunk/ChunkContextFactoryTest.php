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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextKeyDeriver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
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
            new ChunkContextKeyDeriver(),
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
     * A chunk's persisted cache entry is keyed by file content and this
     * context key, never by the mapping — so a `security.yaml` edit, a voter
     * added or removed, or a form binding discovered elsewhere in the project
     * would otherwise replay a verdict computed under the old mapping for a
     * file whose own content never changed.
     *
     * @throws InvalidProjectFileException
     */
    #[DataProvider('mappingChangeCases')]
    public function test_it_derives_a_different_cache_key_when_the_mapping_differs_for_an_otherwise_identical_chunk(SymfonyMapping $before, SymfonyMapping $after): void
    {
        $chunkContextFactory = new ChunkContextFactory(
            self::createStub(AttackerPromptBuilderInterface::class),
            new NullCodeSlicer(),
            new AttackerContextPromptRenderer(),
            new ChunkContextKeyDeriver(),
        );

        $chunk = [ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php class A {}')];

        $chunkContext = $chunkContextFactory->create($chunk, new AttackerAnalysisRequest($chunk, $before), new RiskMarkerIndex([]), true);
        $withMapping = $chunkContextFactory->create($chunk, new AttackerAnalysisRequest($chunk, $after), new RiskMarkerIndex([]), true);

        self::assertNotSame($chunkContext->contextKey, $withMapping->contextKey);
    }

    /**
     * @return iterable<string, array{SymfonyMapping, SymfonyMapping}>
     *
     * @throws InvalidProjectFileException
     */
    public static function mappingChangeCases(): iterable
    {
        yield 'a firewall definition changes' => [
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
                firewallRules: ['main: pattern=^/, security=true'],
            )),
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
                firewallRules: ['main: pattern=^/, security=false'],
            )),
        ];

        yield 'a security.yaml access_control rule tightens or loosens an existing path' => [
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
                routeAccessMap: ['^/reports' => ['ROLE_ADMIN'], '^/admin' => ['ROLE_ADMIN']],
            )),
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
                routeAccessMap: ['^/reports' => ['ROLE_ADMIN'], '^/admin' => ['PUBLIC_ACCESS']],
            )),
        ];

        yield 'a controller action gains a class-level #[IsGranted]' => [
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
                routeAccessControls: [new RouteAccessControl('src/Controller/A.php', 'index', '/admin', ['GET'], true, [], false, false)],
            )),
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
                routeAccessControls: [new RouteAccessControl('src/Controller/A.php', 'index', '/admin', ['GET'], true, [], false, true)],
            )),
        ];

        yield 'a voter starts supporting a new attribute' => [
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
                voterCapabilities: [new VoterCapability('src/Security/Voter/PostVoter.php', 'PostVoter', ['EDIT'], ['Post'])],
            )),
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
                voterCapabilities: [new VoterCapability('src/Security/Voter/PostVoter.php', 'PostVoter', ['EDIT', 'DELETE'], ['Post'])],
            )),
        ];

        yield 'a form binding is discovered' => [
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
                formBindings: [new FormBinding('src/Controller/A.php', 'new', 'App\Form\UserType')],
            )),
        ];

        $projectFile = ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php class A {}');
        $protectedController = ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php #[IsGranted("ROLE_ADMIN")] class A {}');
        yield 'a controller gains a security annotation' => [
            SymfonyMapping::of(ProjectFileInventory::fromGroups(['controllers' => [$projectFile]]), new AccessControlMap()),
            SymfonyMapping::of(ProjectFileInventory::fromGroups(['controllers' => [$protectedController]]), new AccessControlMap()),
        ];
    }

    /**
     * Project scanning makes no ordering guarantee, so two scans of the same
     * unchanged codebase must not produce different cache keys merely because
     * the parsers visited the same routes and form bindings in a different
     * order.
     *
     * @throws InvalidProjectFileException
     */
    public function test_context_key_is_independent_of_the_mappings_internal_ordering(): void
    {
        $chunkContextFactory = new ChunkContextFactory(
            self::createStub(AttackerPromptBuilderInterface::class),
            new NullCodeSlicer(),
            new AttackerContextPromptRenderer(),
            new ChunkContextKeyDeriver(),
        );

        $chunk = [ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php class A {}')];

        $formBindingA = new FormBinding('src/Controller/A.php', 'new', 'App\Form\UserType');
        $formBindingB = new FormBinding('src/Controller/B.php', 'edit', 'App\Form\PostType');

        $forwardOrder = new AttackerAnalysisRequest($chunk, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
            routeAccessMap: ['^/admin' => ['ROLE_ADMIN'], '^/reports' => ['ROLE_USER']],
            formBindings: [$formBindingA, $formBindingB],
        )));
        $reverseOrder = new AttackerAnalysisRequest($chunk, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
            routeAccessMap: ['^/reports' => ['ROLE_USER'], '^/admin' => ['ROLE_ADMIN']],
            formBindings: [$formBindingB, $formBindingA],
        )));

        $chunkContext = $chunkContextFactory->create($chunk, $forwardOrder, new RiskMarkerIndex([]), true);
        $reverse = $chunkContextFactory->create($chunk, $reverseOrder, new RiskMarkerIndex([]), true);

        self::assertSame($chunkContext->contextKey, $reverse->contextKey);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_context_key_stays_empty_for_a_mapping_carrying_no_access_control_data(): void
    {
        $chunkContextFactory = new ChunkContextFactory(
            self::createStub(AttackerPromptBuilderInterface::class),
            new NullCodeSlicer(),
            new AttackerContextPromptRenderer(),
            new ChunkContextKeyDeriver(),
        );

        $projectFile = ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php class A {}');
        $chunk = [$projectFile];
        $attackerAnalysisRequest = new AttackerAnalysisRequest($chunk, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        $chunkContext = $chunkContextFactory->create($chunk, $attackerAnalysisRequest, new RiskMarkerIndex([]), true);

        self::assertSame('', $chunkContext->contextKey);
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
            new ChunkContextKeyDeriver(),
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
            new ChunkContextKeyDeriver(),
        );

        $projectFile = ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', "<?php\nORIGINAL_ONLY_TOKEN\n// more");
        $chunk = [$projectFile];
        $attackerAnalysisRequest = new AttackerAnalysisRequest($chunk, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        $chunkContext = $chunkContextFactory->create($chunk, $attackerAnalysisRequest, new RiskMarkerIndex([]), true);

        self::assertStringContainsString('SLICED_ONLY_TOKEN', $chunkContext->userMessage);
    }
}
