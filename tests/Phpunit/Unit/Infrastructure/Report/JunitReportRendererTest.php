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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JunitReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;

final class JunitReportRendererTest extends AbstractReportRendererTestCase
{
    #[Override]
    protected function createRenderer(): ReportRendererInterface
    {
        return new JunitReportRenderer();
    }

    public function test_it_advertises_the_junit_format(): void
    {
        self::assertSame('junit', $this->renderer->format());
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
        self::assertStringContainsString('CWE: '.VulnerabilityType::SQL_INJECTION->cweReference(), $failure->textContent);
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
    public function test_it_strips_xml_illegal_control_characters(): void
    {
        $illegalCharacters = implode('', array_map('chr', [...range(0x00, 0x08), 0x0B, 0x0C, ...range(0x0E, 0x1F)]));
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, \sprintf('Bad%sTitle', $illegalCharacters), 0.9),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative(\sprintf('Desc%sEnd', $illegalCharacters), 'vector', 'proof', \sprintf('Rem%sEnd', $illegalCharacters)),
            '$q',
        )->withReviewerValidation(true);

        $domDocument = $this->decodeJunit($this->makeReport($vulnerability));

        $testcase = $domDocument->getElementsByTagName('testcase')->item(0);
        self::assertNotNull($testcase);
        self::assertSame('BadTitle (src/Foo.php:1)', $testcase->getAttribute('name'));

        $failure = $domDocument->getElementsByTagName('failure')->item(0);
        self::assertNotNull($failure);
        self::assertStringContainsString('DescEnd', $failure->textContent);
        self::assertStringContainsString('RemEnd', $failure->textContent);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_it_pretty_prints_the_document(): void
    {
        $output = $this->renderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString("<testsuites>\n  <testsuite", $output);
    }

    private function decodeJunit(AuditReport $auditReport): DOMDocument
    {
        $output = $this->renderer->render($auditReport);

        $domDocument = new DOMDocument();
        self::assertTrue($domDocument->loadXML($output));
        self::assertSame('testsuites', $domDocument->documentElement?->nodeName);

        return $domDocument;
    }
}
