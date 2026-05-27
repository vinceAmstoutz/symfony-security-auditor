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
        $request = new AttackerAnalysisRequest([], SymfonyMapping::create());

        self::assertFalse($request->bypassCache);
    }

    public function test_previous_findings_default_to_empty(): void
    {
        $request = new AttackerAnalysisRequest([], SymfonyMapping::create());

        self::assertSame([], $request->previousFindings);
    }

    public function test_it_exposes_the_constructor_arguments(): void
    {
        $files = [ProjectFile::create('src/A.php', '/app/src/A.php', '<?php')];
        $mapping = SymfonyMapping::create();
        $findings = [$this->makeVulnerability()];

        $request = new AttackerAnalysisRequest($files, $mapping, true, $findings);

        self::assertSame($files, $request->files);
        self::assertSame($mapping, $request->symfonyMapping);
        self::assertTrue($request->bypassCache);
        self::assertSame($findings, $request->previousFindings);
    }

    public function test_with_files_and_findings_replaces_both_and_preserves_mapping_and_bypass(): void
    {
        $mapping = SymfonyMapping::create();
        $original = new AttackerAnalysisRequest(
            [ProjectFile::create('src/A.php', '/app/src/A.php', '<?php')],
            $mapping,
            true,
            [],
        );

        $newFiles = [ProjectFile::create('src/B.php', '/app/src/B.php', '<?php')];
        $newFindings = [$this->makeVulnerability()];
        $derived = $original->withFilesAndFindings($newFiles, $newFindings);

        self::assertSame($newFiles, $derived->files);
        self::assertSame($newFindings, $derived->previousFindings);
        self::assertSame($mapping, $derived->symfonyMapping);
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
