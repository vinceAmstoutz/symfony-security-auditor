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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Report;

use DOMDocument;
use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JunitReportRenderer;

final class JunitReportRendererTest extends TestCase
{
    private JunitReportRenderer $junitReportRenderer;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/junit_renderer_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
        $this->junitReportRenderer = new JunitReportRenderer();
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmpDir);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_it_reports_each_validated_finding_as_a_failed_testcase(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'src/Repo.php', 12);

        $domDocument = $this->decodeJunit($this->makeReport($vulnerability));

        $testsuite = $domDocument->getElementsByTagName('testsuite')->item(0);
        self::assertNotNull($testsuite);
        self::assertSame('symfony-security-auditor', $testsuite->getAttribute('name'));
        self::assertSame('1', $testsuite->getAttribute('tests'));
        self::assertSame('1', $testsuite->getAttribute('failures'));

        $testcase = $domDocument->getElementsByTagName('testcase')->item(0);
        self::assertNotNull($testcase);
        self::assertSame('sql_injection', $testcase->getAttribute('classname'));
        self::assertSame('Test Vuln (src/Repo.php:12)', $testcase->getAttribute('name'));

        $failure = $domDocument->getElementsByTagName('failure')->item(0);
        self::assertNotNull($failure);
        self::assertSame('high', $failure->getAttribute('type'));
        self::assertSame('Test Vuln', $failure->getAttribute('message'));
        self::assertStringContainsString('Test description', $failure->textContent);
        self::assertStringContainsString('fix', $failure->textContent);
    }

    public function test_it_reports_an_empty_suite_when_no_findings(): void
    {
        $testsuite = $this->decodeJunit($this->makeReport())->getElementsByTagName('testsuite')->item(0);

        self::assertNotNull($testsuite);
        self::assertSame('0', $testsuite->getAttribute('tests'));
        self::assertSame('0', $testsuite->getAttribute('failures'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_it_escapes_xml_metacharacters(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::TWIG_INJECTION, VulnerabilitySeverity::MEDIUM, 'XSS via <script> & "onerror"', 0.9),
            new CodeLocation('src/Tpl.php', 3, 3),
            new VulnerabilityNarrative('desc', 'vector', 'proof', 'fix'),
            '{{ raw }}',
        )->withReviewerValidation(true);

        $domDocument = $this->decodeJunit($this->makeReport($vulnerability));
        $testcase = $domDocument->getElementsByTagName('testcase')->item(0);

        self::assertNotNull($testcase);
        self::assertStringContainsString('XSS via <script> & "onerror"', $testcase->getAttribute('name'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_it_pretty_prints_the_document(): void
    {
        $output = $this->junitReportRenderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString("<testsuites>\n  <testsuite", $output);
    }

    private function decodeJunit(AuditReport $auditReport): DOMDocument
    {
        $output = $this->junitReportRenderer->render($auditReport);

        $domDocument = new DOMDocument();
        self::assertTrue($domDocument->loadXML($output));
        self::assertSame('testsuites', $domDocument->documentElement?->nodeName);

        return $domDocument;
    }

    private function makeReport(Vulnerability ...$vulnerabilities): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        foreach ($vulnerabilities as $vulnerability) {
            $auditContext->addVulnerability($vulnerability);
        }

        return AuditReport::fromContext($auditContext);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    private function makeValidatedVuln(
        VulnerabilityType $vulnerabilityType = VulnerabilityType::SQL_INJECTION,
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
        string $filePath = 'src/Foo.php',
        int $lineStart = 1,
    ): Vulnerability {
        return Vulnerability::of(
            new VulnerabilityClassification($vulnerabilityType, $vulnerabilitySeverity, 'Test Vuln', 0.9),
            new CodeLocation($filePath, $lineStart, $lineStart + 4),
            new VulnerabilityNarrative('Test description', 'inject', "' OR 1=1", 'fix'),
            '$q',
        )->withReviewerValidation(true);
    }
}
