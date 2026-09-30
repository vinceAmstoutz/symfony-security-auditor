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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
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
        self::assertSame(\strlen("<?php\n// SLICED_ONLY_TOKEN"), $chunkContext->promptedFileBytes);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_candidate_findings_are_rendered_into_the_user_message_and_change_the_cache_key(): void
    {
        $chunkContextFactory = new ChunkContextFactory(
            new AttackerPromptBuilder(),
            new NullCodeSlicer(),
            new AttackerContextPromptRenderer(),
            new ChunkContextKeyDeriver(),
        );
        $chunk = [ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php class A {}')];
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $chunkContext = $chunkContextFactory->create($chunk, new AttackerAnalysisRequest($chunk, $symfonyMapping), new RiskMarkerIndex([]), true);
        $withCandidates = $chunkContextFactory->create($chunk, new AttackerAnalysisRequest($chunk, $symfonyMapping, candidateFindings: [$this->makeVulnerability()]), new RiskMarkerIndex([]), true);

        self::assertStringNotContainsString('## Candidate Findings From a First-Pass Model', $chunkContext->userMessage);
        self::assertStringContainsString('## Candidate Findings From a First-Pass Model', $withCandidates->userMessage);
        self::assertStringContainsString('- sql_injection: src/Controller/A.php:1-2', $withCandidates->userMessage);
        self::assertNotSame($chunkContext->contextKey, $withCandidates->contextKey);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_preambles_precede_the_files_as_confirmed_then_rejected_then_candidates_then_markers(): void
    {
        $chunkContextFactory = new ChunkContextFactory(
            new AttackerPromptBuilder(),
            new NullCodeSlicer(),
            new AttackerContextPromptRenderer(),
            new ChunkContextKeyDeriver(),
        );
        $projectFile = ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php class A {}');
        $chunk = [$projectFile];
        $attackerAnalysisRequest = new AttackerAnalysisRequest(
            $chunk,
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            previousFindings: [$this->makeVulnerability()],
            rejectedFindings: [$this->makeVulnerability()],
            candidateFindings: [$this->makeVulnerability()],
        );

        $chunkContext = $chunkContextFactory->create($chunk, $attackerAnalysisRequest, new RiskMarkerIndex([RiskMarker::create($projectFile->relativePath(), 1, 'sql_injection', 'raw query concatenation')]), true);

        $positions = array_map(
            static fn (string $heading): int => (int) strpos($chunkContext->userMessage, $heading),
            [
                '## Patterns Already Confirmed in Earlier Iterations',
                '## Findings Already Rejected by the Reviewer',
                '## Candidate Findings From a First-Pass Model (Unverified)',
                '## Pre-Scan Risk Markers (Deterministic Hints)',
                '<?php class A {}',
            ],
        );
        $sorted = $positions;
        sort($sorted);
        self::assertSame($sorted, $positions);
        self::assertSame(0, $positions[0]);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_factory_reused_across_requests_renders_each_requests_own_findings(): void
    {
        $chunkContextFactory = new ChunkContextFactory(new AttackerPromptBuilder(), new NullCodeSlicer(), new AttackerContextPromptRenderer(), new ChunkContextKeyDeriver());
        $chunk = [ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php class A {}')];
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());
        $first = new AttackerAnalysisRequest($chunk, $symfonyMapping, rejectedFindings: [$this->makeVulnerability('src/Rejected/First.php')]);
        $second = new AttackerAnalysisRequest($chunk, $symfonyMapping, previousFindings: [$this->makeVulnerability('src/Confirmed/Second.php')]);

        $chunkContext = $chunkContextFactory->create($chunk, $first, new RiskMarkerIndex([]), true);
        $secondContext = $chunkContextFactory->create($chunk, $second, new RiskMarkerIndex([]), true);
        $firstAgain = $chunkContextFactory->create($chunk, $first, new RiskMarkerIndex([]), true);

        self::assertStringContainsString('src/Rejected/First.php', $chunkContext->userMessage);
        self::assertStringNotContainsString('src/Rejected/First.php', $secondContext->userMessage);
        self::assertStringContainsString('src/Confirmed/Second.php', $secondContext->userMessage);
        self::assertStringNotContainsString('src/Confirmed/Second.php', $chunkContext->userMessage);
        self::assertSame($chunkContext->userMessage, $firstAgain->userMessage);
        self::assertSame($chunkContext->contextKey, $firstAgain->contextKey);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerability(string $filePath = 'src/Controller/A.php'): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'T', 0.9),
            new CodeLocation($filePath, 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_only_the_candidates_on_the_chunks_own_files_are_rendered(): void
    {
        $chunkContextFactory = new ChunkContextFactory(
            new AttackerPromptBuilder(),
            new NullCodeSlicer(),
            new AttackerContextPromptRenderer(),
            new ChunkContextKeyDeriver(),
        );
        $chunk = [ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php class A {}')];
        $attackerAnalysisRequest = new AttackerAnalysisRequest(
            $chunk,
            SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()),
            candidateFindings: [$this->makeVulnerability('./src/Controller/A.php'), $this->makeVulnerability('src/Controller/B.php')],
        );

        $chunkContext = $chunkContextFactory->create($chunk, $attackerAnalysisRequest, new RiskMarkerIndex([]), true);

        self::assertStringContainsString('- sql_injection: ./src/Controller/A.php:1-2', $chunkContext->userMessage);
        self::assertStringNotContainsString('src/Controller/B.php', $chunkContext->userMessage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_candidate_on_another_file_leaves_the_chunks_prompt_and_cache_key_untouched(): void
    {
        $chunkContextFactory = new ChunkContextFactory(
            new AttackerPromptBuilder(),
            new NullCodeSlicer(),
            new AttackerContextPromptRenderer(),
            new ChunkContextKeyDeriver(),
        );
        $chunk = [ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php class A {}')];
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $chunkContext = $chunkContextFactory->create($chunk, new AttackerAnalysisRequest($chunk, $symfonyMapping), new RiskMarkerIndex([]), true);
        $withACandidateElsewhere = $chunkContextFactory->create($chunk, new AttackerAnalysisRequest($chunk, $symfonyMapping, candidateFindings: [$this->makeVulnerability('src/Controller/B.php')]), new RiskMarkerIndex([]), true);

        self::assertSame($chunkContext->userMessage, $withACandidateElsewhere->userMessage);
        self::assertSame($chunkContext->contextKey, $withACandidateElsewhere->contextKey);
    }
}
