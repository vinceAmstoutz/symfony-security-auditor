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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class AuditContextTest extends TestCase
{
    private string $tmpDir;

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_creates_for_valid_project_path(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        self::assertSame($this->tmpDir, $auditContext->projectPath());
        self::assertStringStartsWith('AUDIT-', $auditContext->auditId());
        self::assertEmpty($auditContext->projectFiles());
        self::assertEmpty($auditContext->vulnerabilities());
        self::assertNull($auditContext->mapping());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_accepted_fingerprints_default_to_an_empty_list(): void
    {
        self::assertSame([], AuditContext::forProject($this->tmpDir)->acceptedFingerprints());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_returns_the_accepted_fingerprints_it_was_created_with(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: ['SSA-AAA', 'SSA-BBB']);

        self::assertSame(['SSA-AAA', 'SSA-BBB'], $auditContext->acceptedFingerprints());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_consumed_baseline_fingerprints_default_to_an_empty_list(): void
    {
        self::assertSame([], AuditContext::forProject($this->tmpDir)->consumedBaselineFingerprints());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_consumes_a_baseline_credit_and_records_it_as_consumed(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: ['SSA-AAA']);

        self::assertTrue($auditContext->consumeBaselineCredit('SSA-AAA'));
        self::assertSame(['SSA-AAA'], $auditContext->consumedBaselineFingerprints());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_refuses_to_consume_a_baseline_credit_that_was_never_accepted(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        self::assertFalse($auditContext->consumeBaselineCredit('SSA-AAA'));
        self::assertSame([], $auditContext->consumedBaselineFingerprints());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_exhausts_a_baseline_credit_after_it_has_been_consumed_once(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: ['SSA-AAA']);

        self::assertTrue($auditContext->consumeBaselineCredit('SSA-AAA'));
        self::assertFalse($auditContext->consumeBaselineCredit('SSA-AAA'));
        self::assertSame(['SSA-AAA'], $auditContext->consumedBaselineFingerprints());
    }

    /**
     * A fingerprint accepted twice in the baseline (two distinct originally
     * accepted findings sharing the same fingerprint) grants two credits —
     * `array_count_values()`-style budgeting, not plain membership.
     *
     * @throws InvalidAuditContextException
     */
    public function test_it_grants_one_credit_per_repeated_occurrence_of_an_accepted_fingerprint(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: ['SSA-AAA', 'SSA-AAA']);

        self::assertTrue($auditContext->consumeBaselineCredit('SSA-AAA'));
        self::assertTrue($auditContext->consumeBaselineCredit('SSA-AAA'));
        self::assertFalse($auditContext->consumeBaselineCredit('SSA-AAA'));
        self::assertSame(['SSA-AAA', 'SSA-AAA'], $auditContext->consumedBaselineFingerprints());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('typesXssWasReportedAsBefore')]
    public function test_it_consumes_the_credit_an_xss_finding_has_in_a_baseline_under_the_type_it_was_reported_as_before(VulnerabilityType $vulnerabilityType): void
    {
        $accepted = $this->makeVulnerability('page', VulnerabilitySeverity::HIGH, $vulnerabilityType)->fingerprint();
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: [$accepted]);
        $vulnerability = $this->makeVulnerability('page', VulnerabilitySeverity::HIGH, VulnerabilityType::XSS);

        self::assertTrue($auditContext->consumeBaselineCreditFor($vulnerability));
        self::assertSame([$accepted], $auditContext->consumedBaselineFingerprints());
        self::assertFalse($auditContext->consumeBaselineCreditFor($vulnerability));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_consumes_the_own_credit_of_an_xss_finding_before_the_one_of_a_former_type(): void
    {
        $vulnerability = $this->makeVulnerability('page', VulnerabilitySeverity::HIGH, VulnerabilityType::XSS);
        $former = $this->makeVulnerability('page', VulnerabilitySeverity::HIGH, VulnerabilityType::TWIG_INJECTION);
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: [$former->fingerprint(), $vulnerability->fingerprint()]);

        self::assertTrue($auditContext->consumeBaselineCreditFor($vulnerability));
        self::assertTrue($auditContext->consumeBaselineCreditFor($vulnerability));
        self::assertFalse($auditContext->consumeBaselineCreditFor($vulnerability));
        self::assertSame([$vulnerability->fingerprint(), $former->fingerprint()], $auditContext->consumedBaselineFingerprints());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_consumes_nothing_for_a_finding_of_a_former_type_a_baseline_holds_under_xss(): void
    {
        $vulnerability = $this->makeVulnerability('page', VulnerabilitySeverity::HIGH, VulnerabilityType::XSS);
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: [$vulnerability->fingerprint()]);

        self::assertFalse($auditContext->consumeBaselineCreditFor($this->makeVulnerability('page', VulnerabilitySeverity::HIGH, VulnerabilityType::TWIG_INJECTION)));
        self::assertSame([], $auditContext->consumedBaselineFingerprints());
    }

    /**
     * @return iterable<string, array{VulnerabilityType}>
     */
    public static function typesXssWasReportedAsBefore(): iterable
    {
        yield 'twig_injection' => [VulnerabilityType::TWIG_INJECTION];
        yield 'sensitive_data_exposure' => [VulnerabilityType::SENSITIVE_DATA_EXPOSURE];
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_baseline_skipped_findings_default_to_an_empty_list(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        self::assertSame([], $auditContext->baselineSkippedFindings());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_remembers_the_findings_the_baseline_skipped_in_order(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $vulnerability = $this->makeVulnerability('first', VulnerabilitySeverity::HIGH);
        $second = $this->makeVulnerability('second', VulnerabilitySeverity::LOW);

        $auditContext->recordBaselineSkippedFinding($vulnerability);
        $auditContext->recordBaselineSkippedFinding($second);

        self::assertSame([$vulnerability, $second], $auditContext->baselineSkippedFindings());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_audit_id_matches_expected_format(): void
    {
        for ($i = 0; $i < 64; ++$i) {
            self::assertMatchesRegularExpression(
                '/^AUDIT-[A-F0-9]{8}$/',
                AuditContext::forProject($this->tmpDir)->auditId(),
            );
        }
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_throws_on_invalid_project_path(): void
    {
        $this->expectException(InvalidAuditContextException::class);
        AuditContext::forProject('/nonexistent/path/xyz');
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_strips_trailing_slash_from_project_path(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir.'/');

        self::assertSame($this->tmpDir, $auditContext->projectPath());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_the_filesystem_root_does_not_collapse_to_an_empty_project_path(): void
    {
        $auditContext = AuditContext::forProject('/');

        self::assertSame('/', $auditContext->projectPath());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_it_accepts_and_returns_project_files(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $files = [
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
            ProjectFile::create('src/B.php', '/app/src/B.php', '<?php'),
        ];

        $auditContext->setProjectFiles($files);

        self::assertCount(2, $auditContext->projectFiles());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_files_falls_back_to_project_files_when_never_explicitly_set(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $files = [ProjectFile::create('src/A.php', '/app/src/A.php', '<?php')];

        $auditContext->setProjectFiles($files);

        self::assertSame($files, $auditContext->mappingFiles());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_files_can_be_set_independently_of_the_diff_filtered_project_files(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $projectFiles = [ProjectFile::create('src/Changed.php', '/app/src/Changed.php', '<?php')];
        $mappingFiles = [
            ProjectFile::create('src/Changed.php', '/app/src/Changed.php', '<?php'),
            ProjectFile::create('src/Unchanged.php', '/app/src/Unchanged.php', '<?php'),
        ];

        $auditContext->setProjectFiles($projectFiles);
        $auditContext->setMappingFiles($mappingFiles);

        self::assertSame($projectFiles, $auditContext->projectFiles());
        self::assertSame($mappingFiles, $auditContext->mappingFiles());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_files_discovered_falls_back_to_the_count_of_mapping_files_when_never_explicitly_set(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setMappingFiles([
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
            ProjectFile::create('src/B.php', '/app/src/B.php', '<?php'),
        ]);

        self::assertSame(2, $auditContext->filesDiscovered());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_files_discovered_can_be_set_independently_of_the_mapping_files(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setMappingFiles([
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
            ProjectFile::create('src/B.php', '/app/src/B.php', '<?php'),
        ]);

        $auditContext->setFilesDiscovered(0);

        self::assertSame(0, $auditContext->filesDiscovered());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_accepts_mapping(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $auditContext->setMapping($symfonyMapping);

        self::assertSame($symfonyMapping, $auditContext->mapping());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_stores_and_filters_vulnerabilities(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $vulnerability = $this->makeVulnerability('v1', VulnerabilitySeverity::CRITICAL)
            ->withReviewerValidation(true);
        $notValidated = $this->makeVulnerability('v2', VulnerabilitySeverity::HIGH);

        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($notValidated);

        self::assertCount(2, $auditContext->vulnerabilities());
        self::assertCount(1, $auditContext->validatedVulnerabilities());
        self::assertCount(1, $auditContext->criticalVulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_critical_vulnerabilities_requires_both_critical_severity_and_reviewer_validation(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        // critical + validated → included
        $vulnerability = $this->makeVulnerability('cv', VulnerabilitySeverity::CRITICAL)
            ->withReviewerValidation(true);
        // critical + NOT validated → excluded
        $criticalUnvalidated = $this->makeVulnerability('cu', VulnerabilitySeverity::CRITICAL);
        // high + validated → excluded (not critical)
        $highValidated = $this->makeVulnerability('hv', VulnerabilitySeverity::HIGH)
            ->withReviewerValidation(true);
        // high + NOT validated → excluded
        $highUnvalidated = $this->makeVulnerability('hu', VulnerabilitySeverity::HIGH);

        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($criticalUnvalidated);
        $auditContext->addVulnerability($highValidated);
        $auditContext->addVulnerability($highUnvalidated);

        $criticals = $auditContext->criticalVulnerabilities();

        self::assertCount(1, $criticals);
        $only = array_values($criticals)[0];
        self::assertSame('Test cv', $only->title());
        self::assertTrue($only->isReviewerValidated());
        self::assertSame(VulnerabilitySeverity::CRITICAL, $only->severity());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_removes_only_the_vulnerability_with_the_given_id(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $vulnerability = $this->makeVulnerability('v1', VulnerabilitySeverity::HIGH);
        $kept = $this->makeVulnerability('v2', VulnerabilitySeverity::HIGH);
        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($kept);

        $auditContext->removeVulnerability($vulnerability->id());

        self::assertSame([$kept->id() => $kept], $auditContext->vulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_replaces_vulnerability_by_id(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $vulnerability = $this->makeVulnerability('v1', VulnerabilitySeverity::HIGH);
        $auditContext->addVulnerability($vulnerability);

        $updated = $vulnerability->withReviewerValidation(true);
        $auditContext->replaceVulnerability($updated);

        self::assertCount(1, $auditContext->vulnerabilities());
        $stored = array_values($auditContext->vulnerabilities())[0];
        self::assertTrue($stored->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_calculates_risk_score_from_validated_vulnerabilities(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $vulnerability = $this->makeVulnerability('v1', VulnerabilitySeverity::CRITICAL)
            ->withReviewerValidation(true); // score 10
        $high = $this->makeVulnerability('v2', VulnerabilitySeverity::HIGH)
            ->withReviewerValidation(true); // score 7
        $notValidated = $this->makeVulnerability('v3', VulnerabilitySeverity::CRITICAL); // not counted

        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($high);
        $auditContext->addVulnerability($notValidated);

        self::assertSame(17, $auditContext->riskScore());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_stores_and_retrieves_metadata(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditContext->setMeta('foo', 'bar');
        $auditContext->setMeta('count', 42);

        self::assertSame('bar', $auditContext->getMeta('foo'));
        self::assertSame(42, $auditContext->getMeta('count'));
        self::assertNull($auditContext->getMeta('missing'));
        self::assertSame('default', $auditContext->getMeta('missing', 'default'));
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/audit_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_coverage_starts_empty(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        self::assertSame([], $auditContext->coverage());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_record_coverage_appends_entry_with_stage_file_and_status(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditContext->recordCoverage('attacker', 'src/Controller/A.php', 'analyzed');

        self::assertSame(
            [['stage' => 'attacker', 'file' => 'src/Controller/A.php', 'status' => 'analyzed']],
            $auditContext->coverage(),
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_record_coverage_preserves_insertion_order_for_multiple_entries(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');
        $auditContext->recordCoverage('reviewer', 'src/A.php', 'validated');
        $auditContext->recordCoverage('attacker', 'src/B.php', 'cached');

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'attacker', 'file' => 'src/B.php', 'status' => 'cached'],
            ],
            $auditContext->coverage(),
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_record_coverage_allows_duplicate_entries_for_same_file_stage_status(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');
        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');

        self::assertCount(2, $auditContext->coverage());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_scan_paths_default_is_empty_list(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        self::assertSame([], $auditContext->scanPaths());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_for_project_stores_scan_paths(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir, ['apps/api/src', 'libs/shared']);

        self::assertSame(['apps/api/src', 'libs/shared'], $auditContext->scanPaths());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_cache_bypassed_default_is_false(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        self::assertFalse($auditContext->isCacheBypassed());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_for_project_stores_cache_bypassed_flag(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir, [], true);

        self::assertTrue($auditContext->isCacheBypassed());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_drain_reviewed_findings_starts_empty(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        self::assertSame([], $auditContext->drainReviewedFindings());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_drain_reviewed_findings_returns_every_recorded_finding_in_order(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $vulnerability = $this->makeVulnerability('v1', VulnerabilitySeverity::HIGH);
        $second = $this->makeVulnerability('v2', VulnerabilitySeverity::HIGH);

        $auditContext->recordReviewedFinding($vulnerability);
        $auditContext->recordReviewedFinding($second);

        self::assertSame([$vulnerability, $second], $auditContext->drainReviewedFindings());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_drain_reviewed_findings_clears_the_buffer(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordReviewedFinding($this->makeVulnerability('v1', VulnerabilitySeverity::HIGH));

        $auditContext->drainReviewedFindings();

        self::assertSame([], $auditContext->drainReviewedFindings());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_drain_found_vulnerabilities_starts_empty(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        self::assertSame([], $auditContext->drainFoundVulnerabilities());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_drain_found_vulnerabilities_returns_every_recorded_candidate_in_order(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $vulnerability = $this->makeVulnerability('v1', VulnerabilitySeverity::HIGH);
        $second = $this->makeVulnerability('v2', VulnerabilitySeverity::HIGH);

        $auditContext->recordFoundVulnerability($vulnerability);
        $auditContext->recordFoundVulnerability($second);

        self::assertSame([$vulnerability, $second], $auditContext->drainFoundVulnerabilities());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_drain_found_vulnerabilities_clears_the_buffer(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordFoundVulnerability($this->makeVulnerability('v1', VulnerabilitySeverity::HIGH));

        $auditContext->drainFoundVulnerabilities();

        self::assertSame([], $auditContext->drainFoundVulnerabilities());
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerability(string $discriminator, VulnerabilitySeverity $vulnerabilitySeverity, VulnerabilityType $vulnerabilityType = VulnerabilityType::SQL_INJECTION): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification($vulnerabilityType, $vulnerabilitySeverity, 'Test '.$discriminator, 0.9),
            new CodeLocation('src/'.$discriminator.'.php', 1, 5),
            new VulnerabilityNarrative('Test', 'Inject SQL', "' OR 1=1--", 'Use prepared statements'),
            '$query',
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_remembers_only_the_findings_the_reviewer_rejected(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $vulnerability = $this->rejectionCandidate('src/Rejected.php');
        $failed = $this->rejectionCandidate('src/Failed.php');

        $auditContext->recordRejectedFinding($vulnerability);

        self::assertTrue($auditContext->wasRejectedByReviewer($vulnerability));
        self::assertFalse($auditContext->wasRejectedByReviewer($failed));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function rejectionCandidate(string $filePath): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Candidate', 0.9),
            new CodeLocation($filePath, 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
