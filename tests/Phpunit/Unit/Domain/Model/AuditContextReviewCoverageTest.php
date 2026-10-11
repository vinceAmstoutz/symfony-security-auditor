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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\UnanalyzedFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class AuditContextReviewCoverageTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_finding_review_is_recorded_as_a_reviewer_entry_of_the_findings_file(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        $auditContext->recordFindingReview($this->findingAt('src/A.php', 10), 'validated');

        self::assertSame([['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated']], $auditContext->coverage());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('verdicts')]
    public function test_a_verdict_supersedes_the_failures_recorded_earlier_for_the_same_finding(string $verdict): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $vulnerability = $this->findingAt('src/A.php', 10);

        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');
        $auditContext->recordFindingReview($vulnerability, 'errored');
        $auditContext->recordCoverage('attacker', 'src/B.php', 'analyzed');
        $auditContext->recordFindingReview($vulnerability, 'aborted');
        $auditContext->recordFindingReview($vulnerability, $verdict);

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'attacker', 'file' => 'src/B.php', 'status' => 'analyzed'],
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => $verdict],
            ],
            $auditContext->coverage(),
        );
        self::assertSame([], UnanalyzedFiles::in($auditContext->coverage()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function verdicts(): iterable
    {
        yield 'validated' => ['validated'];
        yield 'rejected' => ['rejected'];
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_verdict_leaves_the_failure_of_another_finding_of_the_same_file(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        $auditContext->recordFindingReview($this->findingAt('src/A.php', 10), 'errored');
        $auditContext->recordFindingReview($this->findingAt('src/A.php', 40), 'validated');

        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
            ],
            $auditContext->coverage(),
        );
        self::assertSame(['src/A.php'], UnanalyzedFiles::in($auditContext->coverage()));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_failure_recorded_after_a_verdict_still_counts(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $vulnerability = $this->findingAt('src/A.php', 10);

        $auditContext->recordFindingReview($vulnerability, 'validated');
        $auditContext->recordFindingReview($vulnerability, 'errored');

        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'errored'],
            ],
            $auditContext->coverage(),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_second_verdict_for_a_finding_keeps_the_first(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $vulnerability = $this->findingAt('src/A.php', 10);

        $auditContext->recordFindingReview($vulnerability, 'validated');
        $auditContext->recordFindingReview($vulnerability, 'rejected');

        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'rejected'],
            ],
            $auditContext->coverage(),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_failure_recorded_after_a_superseded_one_is_the_one_left_in_the_ledger(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $vulnerability = $this->findingAt('src/A.php', 10);

        $auditContext->recordFindingReview($vulnerability, 'errored');
        $auditContext->recordFindingReview($vulnerability, 'validated');
        $auditContext->recordFindingReview($vulnerability, 'aborted');

        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'aborted'],
            ],
            $auditContext->coverage(),
        );
        self::assertSame(['src/A.php'], UnanalyzedFiles::in($auditContext->coverage()));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function findingAt(string $filePath, int $lineStart): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'SQLi', 0.9),
            new CodeLocation($filePath, $lineStart, $lineStart + 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
