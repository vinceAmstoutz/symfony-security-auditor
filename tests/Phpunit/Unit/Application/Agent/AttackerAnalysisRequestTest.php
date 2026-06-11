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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class AttackerAnalysisRequestTest extends TestCase
{
    public function test_bypass_cache_defaults_to_false(): void
    {
        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::create());

        self::assertFalse($attackerAnalysisRequest->bypassCache);
    }

    public function test_previous_findings_default_to_empty(): void
    {
        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::create());

        self::assertSame([], $attackerAnalysisRequest->previousFindings);
    }

    public function test_rejected_findings_default_to_empty(): void
    {
        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::create());

        self::assertSame([], $attackerAnalysisRequest->rejectedFindings);
    }

    public function test_it_exposes_rejected_findings_from_the_constructor(): void
    {
        $rejected = [$this->makeVulnerability()];

        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::create(), false, [], $rejected);

        self::assertSame($rejected, $attackerAnalysisRequest->rejectedFindings);
    }

    public function test_with_files_and_findings_preserves_rejected_findings(): void
    {
        $rejected = [$this->makeVulnerability()];
        $attackerAnalysisRequest = new AttackerAnalysisRequest([], SymfonyMapping::create(), true, [], $rejected);

        $derived = $attackerAnalysisRequest->withFilesAndFindings([], []);

        self::assertSame($rejected, $derived->rejectedFindings);
    }

    public function test_it_exposes_the_constructor_arguments(): void
    {
        $files = [ProjectFile::create('src/A.php', '/app/src/A.php', '<?php')];
        $symfonyMapping = SymfonyMapping::create();
        $findings = [$this->makeVulnerability()];

        $attackerAnalysisRequest = new AttackerAnalysisRequest($files, $symfonyMapping, true, $findings);

        self::assertSame($files, $attackerAnalysisRequest->files);
        self::assertSame($symfonyMapping, $attackerAnalysisRequest->symfonyMapping);
        self::assertTrue($attackerAnalysisRequest->bypassCache);
        self::assertSame($findings, $attackerAnalysisRequest->previousFindings);
    }

    public function test_with_files_and_findings_replaces_both_and_preserves_mapping_and_bypass(): void
    {
        $symfonyMapping = SymfonyMapping::create();
        $attackerAnalysisRequest = new AttackerAnalysisRequest(
            [ProjectFile::create('src/A.php', '/app/src/A.php', '<?php')],
            $symfonyMapping,
            true,
            [],
        );

        $newFiles = [ProjectFile::create('src/B.php', '/app/src/B.php', '<?php')];
        $newFindings = [$this->makeVulnerability()];
        $derived = $attackerAnalysisRequest->withFilesAndFindings($newFiles, $newFindings);

        self::assertSame($newFiles, $derived->files);
        self::assertSame($newFindings, $derived->previousFindings);
        self::assertSame($symfonyMapping, $derived->symfonyMapping);
        self::assertTrue($derived->bypassCache);
    }

    private function makeVulnerability(): Vulnerability
    {
        return Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'T',
            description: 'd',
            filePath: 'src/A.php',
            lineStart: 1,
            lineEnd: 2,
            vulnerableCode: 'c',
            attackVector: 'a',
            proof: 'p',
            remediation: 'r',
            confidence: 0.9,
        );
    }
}
