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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class AttackerAnalysisRequestTest extends TestCase
{
    public function test_bypass_cache_defaults_to_false(): void
    {
        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        self::assertFalse($attackerAnalysisRequest->bypassCache);
    }

    public function test_previous_findings_default_to_empty(): void
    {
        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        self::assertSame([], $attackerAnalysisRequest->previousFindings);
    }

    public function test_rejected_findings_default_to_empty(): void
    {
        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        self::assertSame([], $attackerAnalysisRequest->rejectedFindings);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_exposes_rejected_findings_from_the_constructor(): void
    {
        $rejected = [$this->makeVulnerability()];

        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), false, [], $rejected);

        self::assertSame($rejected, $attackerAnalysisRequest->rejectedFindings);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_with_files_and_candidate_findings_preserves_previous_and_rejected_findings(): void
    {
        $previous = [$this->makeVulnerability()];
        $rejected = [$this->makeVulnerability()];
        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), true, $previous, $rejected);

        $derived = $attackerAnalysisRequest->withFilesAndCandidateFindings([], []);

        self::assertSame($previous, $derived->previousFindings);
        self::assertSame($rejected, $derived->rejectedFindings);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_exposes_the_constructor_arguments(): void
    {
        $files = [ProjectFile::create('src/A.php', '/app/src/A.php', '<?php')];
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());
        $findings = [$this->makeVulnerability()];

        $attackerAnalysisRequest = new AttackerAnalysisRequest($files, $symfonyMapping, true, $findings);

        self::assertSame($files, $attackerAnalysisRequest->files);
        self::assertSame($symfonyMapping, $attackerAnalysisRequest->symfonyMapping);
        self::assertTrue($attackerAnalysisRequest->bypassCache);
        self::assertSame($findings, $attackerAnalysisRequest->previousFindings);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_with_files_and_candidate_findings_replaces_both_and_preserves_mapping_and_bypass(): void
    {
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());
        $attackerAnalysisRequest = new AttackerAnalysisRequest(
            [ProjectFile::create('src/A.php', '/app/src/A.php', '<?php')],
            $symfonyMapping,
            true,
            [],
        );

        $newFiles = [ProjectFile::create('src/B.php', '/app/src/B.php', '<?php')];
        $candidates = [$this->makeVulnerability()];
        $derived = $attackerAnalysisRequest->withFilesAndCandidateFindings($newFiles, $candidates);

        self::assertSame($newFiles, $derived->files);
        self::assertSame($candidates, $derived->candidateFindings);
        self::assertSame($symfonyMapping, $derived->symfonyMapping);
        self::assertTrue($derived->bypassCache);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_the_tools_default_to_the_files_to_analyze(): void
    {
        $files = [ProjectFile::create('src/A.php', '/app/src/A.php', '<?php')];

        $attackerAnalysisRequest = new AttackerAnalysisRequest($files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        self::assertSame($files, $attackerAnalysisRequest->filesForTools());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_the_tools_read_the_files_the_request_names_for_them(): void
    {
        $files = [ProjectFile::create('src/A.php', '/app/src/A.php', '<?php')];
        $toolFiles = [...$files, ProjectFile::create('src/B.php', '/app/src/B.php', '<?php')];

        $attackerAnalysisRequest = new AttackerAnalysisRequest($files, SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), toolFiles: $toolFiles);

        self::assertSame($toolFiles, $attackerAnalysisRequest->filesForTools());
        self::assertSame($files, $attackerAnalysisRequest->files);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_with_files_and_candidate_findings_keeps_the_scope_the_tools_were_given_and_leaves_an_unnamed_one_to_the_new_files(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', '<?php');
        $b = ProjectFile::create('src/B.php', '/app/src/B.php', '<?php');
        $c = ProjectFile::create('src/C.php', '/app/src/C.php', '<?php');
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $attackerAnalysisRequest = (new AttackerAnalysisRequest([$projectFile, $b], $symfonyMapping, toolFiles: [$projectFile, $b, $c]))->withFilesAndCandidateFindings([$projectFile], []);
        $derivedFromUnnamedToolFiles = (new AttackerAnalysisRequest([$projectFile, $b], $symfonyMapping))->withFilesAndCandidateFindings([$projectFile], []);

        self::assertSame([$projectFile, $b, $c], $attackerAnalysisRequest->filesForTools());
        self::assertSame([$projectFile], $derivedFromUnnamedToolFiles->filesForTools());
        self::assertNull($derivedFromUnnamedToolFiles->toolFiles);
        self::assertSame([$projectFile], $derivedFromUnnamedToolFiles->files);
    }

    public function test_candidate_findings_default_to_empty(): void
    {
        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        self::assertSame([], $attackerAnalysisRequest->candidateFindings);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerability(): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'T', 0.9),
            new CodeLocation('src/A.php', 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
