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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Report;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;

/**
 * `audit:diff` and `audit:trend` read reports written by older releases, keyed
 * by finding fingerprint, so the JSON and SARIF documents are a cross-version
 * data contract rather than console output. This pins both: every key path and
 * value type against a committed snapshot, and the fingerprint algorithm
 * against a known input. Adding, renaming, removing or retyping a key fails
 * here — deliberately, so the change is made as a documented schema decision
 * instead of slipping through as a rendering tweak.
 */
final class ReportSchemaFreezeTest extends TestCase
{
    private const string FINGERPRINT_OF_KNOWN_FINDING = 'SSA-EE6A9241E576';

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('renderers')]
    public function test_the_rendered_document_keeps_its_frozen_shape(string $fixture, ReportRendererInterface $reportRenderer): void
    {
        $rendered = $reportRenderer->render($this->frozenReport());
        $decoded = json_decode($rendered, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        self::assertSame($this->frozenShape($fixture), self::shapeOf($decoded));
    }

    public function test_the_finding_fingerprint_algorithm_is_frozen(): void
    {
        self::assertSame(
            self::FINGERPRINT_OF_KNOWN_FINDING,
            Vulnerability::fingerprintOf('sql_injection', 'src/Controller/SearchController.php', 'Frozen finding'),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_json_report_carries_the_frozen_fingerprint_for_a_known_finding(): void
    {
        $decoded = json_decode((new JsonReportRenderer())->render($this->frozenReport()), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        $vulnerabilities = $decoded['vulnerabilities'];
        self::assertIsArray($vulnerabilities);
        $first = $vulnerabilities[0];
        self::assertIsArray($first);

        self::assertSame(self::FINGERPRINT_OF_KNOWN_FINDING, $first['fingerprint']);
    }

    /** @return iterable<string, array{string, ReportRendererInterface}> */
    public static function renderers(): iterable
    {
        yield 'json' => ['report-schema.json', new JsonReportRenderer()];
        yield 'sarif' => ['report-schema.sarif.json', new SarifReportRenderer()];
    }

    /**
     * Replaces every leaf with its type name, so the snapshot pins the document
     * structure without pinning run-specific values (audit id, timestamps,
     * durations, the package version).
     *
     * @param array<array-key, mixed> $decoded
     *
     * @return array<array-key, mixed>
     */
    private static function shapeOf(array $decoded): array
    {
        $shape = [];
        foreach ($decoded as $key => $value) {
            $shape[$key] = \is_array($value) ? self::shapeOf($value) : get_debug_type($value);
        }

        return $shape;
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function frozenReport(): AuditReport
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->addVulnerability(
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'Frozen finding', 0.9),
                new CodeLocation('src/Controller/SearchController.php', 12, 18),
                new VulnerabilityNarrative('Unescaped query parameter', 'GET /search?q=', "' OR 1=1 --", 'Use a parameterized query'),
                '$connection->query($sql)',
            )->withReviewerValidation(true),
        );

        return AuditReport::fromContext($auditContext, AuditCost::of(1_000, 500, 0.05, 'claude-opus-5'));
    }

    /**
     * @return array<array-key, mixed>
     */
    private function frozenShape(string $fixture): array
    {
        $contents = file_get_contents(__DIR__.'/Fixture/'.$fixture);
        self::assertIsString($contents);
        $decoded = json_decode($contents, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }
}
