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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Pipeline;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;

final class IngestionStageScrubbedSecretFindingsTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_redacted_credential_is_queued_for_review_as_a_hardcoded_secret_on_its_line(): void
    {
        $file = ProjectFile::create('src/Billing.php', '/p/src/Billing.php', "<?php\n\n\$key = '***REDACTED:aws_access_key***';\n");
        $auditContext = AuditContext::forProject('/p');

        (new IngestionStage($this->scannerReturning([$file]), new NullLogger()))->process($auditContext);

        $findings = $auditContext->drainStaticCandidates();
        self::assertCount(1, $findings);
        self::assertSame(VulnerabilityType::HARDCODED_SECRET, $findings[0]->type());
        self::assertSame('src/Billing.php', $findings[0]->filePath());
        self::assertSame(3, $findings[0]->lineStart());
        self::assertFalse($findings[0]->isReviewerValidated());
        self::assertStringContainsString('aws_access_key', $findings[0]->description());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_static_pre_scan_match_is_queued_for_review_as_a_finding_of_its_mapped_type(): void
    {
        $file = ProjectFile::create('src/Legacy.php', '/p/src/Legacy.php', "<?php\n\nunserialize(\$payload);\n");
        $auditContext = AuditContext::forProject('/p');

        (new IngestionStage($this->scannerReturning([$file]), new NullLogger(), null, new RegexStaticPreScanner([], new NullLogger())))->process($auditContext);

        $findings = $auditContext->drainStaticCandidates();
        self::assertSame(VulnerabilityType::INSECURE_DESERIALIZATION, $findings[0]->type());
        self::assertSame(3, $findings[0]->lineStart());
    }

    /**
     * @param list<ProjectFile> $files
     */
    private function scannerReturning(array $files): ProjectFileScannerInterface
    {
        return new readonly class($files) implements ProjectFileScannerInterface {
            /** @param list<ProjectFile> $files */
            public function __construct(private array $files) {}

            #[Override]
            public function scan(string $projectPath): array
            {
                return $this->files;
            }
        };
    }
}
