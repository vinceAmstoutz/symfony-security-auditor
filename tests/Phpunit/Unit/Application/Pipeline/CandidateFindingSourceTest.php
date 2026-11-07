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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Pipeline;

use Override;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\CandidateFindingSource;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;

final class CandidateFindingSourceTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_lists_the_redacted_secrets_then_the_static_matches_with_their_line_of_code(): void
    {
        $file = ProjectFile::create('src/A.php', '/p/src/A.php', "<?php\n\$k = '***REDACTED:jwt***';\nunserialize(\$x);\n");
        $source = new CandidateFindingSource($this->scannerReturning([
            RiskMarker::create('src/A.php', 3, 'unserialize_call', 'Unsafe.'),
            RiskMarker::create('src/A.php', 2, 'scrubbed_secret', 'Redacted.'),
        ]));

        $candidates = $source->candidatesIn([$file]);

        self::assertCount(2, $candidates);
        self::assertSame(2, $candidates[0]->lineStart());
        self::assertSame(VulnerabilityType::HARDCODED_SECRET, $candidates[0]->type());
        self::assertSame(VulnerabilityType::INSECURE_DESERIALIZATION, $candidates[1]->type());
        self::assertSame('unserialize($x);', $candidates[1]->vulnerableCode());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_marker_beyond_the_end_of_its_file_is_reported_without_code(): void
    {
        $file = ProjectFile::create('src/A.php', '/p/src/A.php', '<?php');
        $source = new CandidateFindingSource($this->scannerReturning([RiskMarker::create('src/A.php', 9, 'unserialize_call', 'Unsafe.')]));

        self::assertSame('', $source->candidatesIn([$file])[0]->vulnerableCode());
    }

    /**
     * @param list<RiskMarker> $markers
     */
    private function scannerReturning(array $markers): StaticPreScannerInterface
    {
        return new readonly class($markers) implements StaticPreScannerInterface {
            /** @param list<RiskMarker> $markers */
            public function __construct(private array $markers) {}

            #[Override]
            public function scan(array $files): array
            {
                return $this->markers;
            }
        };
    }
}
