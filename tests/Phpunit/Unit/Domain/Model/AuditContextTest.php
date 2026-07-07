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
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
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
     */
    private function makeVulnerability(string $discriminator, VulnerabilitySeverity $vulnerabilitySeverity): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, $vulnerabilitySeverity, 'Test '.$discriminator, 0.9),
            new CodeLocation('src/'.$discriminator.'.php', 1, 5),
            new VulnerabilityNarrative('Test', 'Inject SQL', "' OR 1=1--", 'Use prepared statements'),
            '$query',
        );
    }
}
