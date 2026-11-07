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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ScrubbedSecretFindings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class ScrubbedSecretFindingsTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_each_redacted_line_is_one_finding_with_its_line_number_and_kind(): void
    {
        $file = ProjectFile::create('src/A.php', '/p/src/A.php', "<?php\n\$a = '***REDACTED:aws_access_key***';\n\$b = 1;\n  \$c = '***REDACTED:jwt***';\n");

        $findings = ScrubbedSecretFindings::in($file);

        self::assertCount(2, $findings);
        self::assertSame(2, $findings[0]->lineStart());
        self::assertSame(2, $findings[0]->lineEnd());
        self::assertSame(4, $findings[1]->lineStart());
        self::assertSame(VulnerabilityType::HARDCODED_SECRET, $findings[0]->type());
        self::assertSame(VulnerabilitySeverity::HIGH, $findings[0]->severity());
        self::assertSame(0.95, $findings[0]->confidence());
        self::assertSame('src/A.php', $findings[0]->filePath());
        self::assertSame('Hardcoded secret committed in source', $findings[0]->title());
        self::assertSame("\$a = '***REDACTED:aws_access_key***';", $findings[0]->vulnerableCode());
        self::assertSame("\$c = '***REDACTED:jwt***';", $findings[1]->vulnerableCode());
        self::assertStringContainsString('"jwt"', $findings[1]->description());
        self::assertStringContainsString('"jwt"', $findings[1]->proof());
        self::assertFalse($findings[0]->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_file_with_nothing_redacted_has_no_finding(): void
    {
        self::assertSame([], ScrubbedSecretFindings::in(ProjectFile::create('src/A.php', '/p/src/A.php', "<?php\necho 1;\n")));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_file_withheld_by_the_scrubber_is_not_reported_as_a_secret(): void
    {
        self::assertSame([], ScrubbedSecretFindings::in(ProjectFile::create('src/A.php', '/p/src/A.php', '***REDACTED:unscannable***')));
    }
}
