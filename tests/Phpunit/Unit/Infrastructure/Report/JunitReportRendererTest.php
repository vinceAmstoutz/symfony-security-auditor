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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
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
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
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
        self::assertStringContainsString('CWE: '.VulnerabilityType::SQL_INJECTION->cwe()->label(), $failure->textContent);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_reports_an_empty_suite_when_no_findings(): void
    {
        $testsuite = $this->decodeJunit($this->makeReport())->getElementsByTagName('testsuite')->item(0);

        self::assertNotNull($testsuite);
        self::assertSame('0', $testsuite->getAttribute('tests'));
        self::assertSame('0', $testsuite->getAttribute('failures'));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_complete_audit_reports_no_error(): void
    {
        $domDocument = $this->decodeJunit($this->makeReport());

        $testsuite = $domDocument->getElementsByTagName('testsuite')->item(0);
        self::assertNotNull($testsuite);
        self::assertSame('0', $testsuite->getAttribute('errors'));
        self::assertSame(0, $domDocument->getElementsByTagName('error')->length);
    }

    /**
     * A CI test-report panel reads an empty passing suite as a clean run, so
     * an audit that could not analyze every file fails a test case of its own.
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_incomplete_audit_errors_a_completeness_testcase_counted_in_the_suite(): void
    {
        $domDocument = $this->decodeJunit($this->makeIncompleteReport($this->makeValidatedVuln()));

        $testsuite = $domDocument->getElementsByTagName('testsuite')->item(0);
        self::assertNotNull($testsuite);
        self::assertSame('2', $testsuite->getAttribute('tests'));
        self::assertSame('1', $testsuite->getAttribute('failures'));
        self::assertSame('1', $testsuite->getAttribute('errors'));

        $testcase = $domDocument->getElementsByTagName('testcase')->item(0);
        self::assertNotNull($testcase);
        self::assertSame('symfony-security-auditor', $testcase->getAttribute('classname'));
        self::assertSame('Audit completeness', $testcase->getAttribute('name'));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_the_completeness_error_states_the_notice_and_lists_the_unanalyzed_files(): void
    {
        $error = $this->decodeJunit($this->makeIncompleteReport())->getElementsByTagName('error')->item(0);

        self::assertNotNull($error);
        self::assertSame('incomplete', $error->getAttribute('type'));
        self::assertStringStartsWith('Audit incomplete: 2 file(s) could not be fully analyzed', $error->getAttribute('message'));
        self::assertSame("Files not fully analyzed:\nsrc/Controller/Failed.php\nsrc/Controller/Unreached.php", $error->textContent);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_the_completeness_error_of_a_run_that_made_no_llm_call_states_the_notice(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([ProjectFile::create('src/A.php', $this->tmpDir.'/src/A.php', '<?php')]);

        $error = $this->decodeJunit(AuditReport::fromContext($auditContext))->getElementsByTagName('error')->item(0);

        self::assertNotNull($error);
        self::assertStringStartsWith('Audit incomplete: none of the 1 file(s) in scope was analyzed', $error->textContent);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_the_completeness_error_strips_illegal_characters_from_a_file_name(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordCoverage('attacker', "src/Fail\x01ed.php", 'errored');

        $error = $this->decodeJunit(AuditReport::fromContext($auditContext))->getElementsByTagName('error')->item(0);

        self::assertNotNull($error);
        self::assertStringEndsWith("\nsrc/Failed.php", $error->textContent);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
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
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
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
     * A Unicode bidirectional override is valid XML text — the illegal-XML-char
     * filter never touches it — so it reaches any JUnit-consuming CI viewer
     * unchanged, enabling a Trojan-Source-style visual reorder of the
     * displayed finding title/description/remediation.
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_strips_a_bidirectional_override_from_title_description_and_remediation(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, "Safe\u{202E}Title", 0.9),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative("Safe\u{202E}Desc", 'vector', 'proof', "Safe\u{202E}Fix"),
            '$q',
        )->withReviewerValidation(true);

        $domDocument = $this->decodeJunit($this->makeReport($vulnerability));

        $testcase = $domDocument->getElementsByTagName('testcase')->item(0);
        self::assertNotNull($testcase);
        self::assertStringNotContainsString("\u{202E}", $testcase->getAttribute('name'));

        $failure = $domDocument->getElementsByTagName('failure')->item(0);
        self::assertNotNull($failure);
        self::assertStringNotContainsString("\u{202E}", $failure->textContent);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_strips_illegal_control_characters_from_the_file_path(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Title', 0.9),
            new CodeLocation("src/Fo\x08o.php", 1, 5),
            new VulnerabilityNarrative('desc', 'vector', 'proof', 'fix'),
            '$q',
        )->withReviewerValidation(true);

        $domDocument = $this->decodeJunit($this->makeReport($vulnerability));

        $testcase = $domDocument->getElementsByTagName('testcase')->item(0);
        self::assertNotNull($testcase);
        self::assertSame('Title (src/Foo.php:1)', $testcase->getAttribute('name'));

        $failure = $domDocument->getElementsByTagName('failure')->item(0);
        self::assertNotNull($failure);
        self::assertStringContainsString('Location: src/Foo.php:1-5', $failure->textContent);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_strips_non_characters_that_are_valid_utf8_but_illegal_xml(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, "Bad\u{FFFF}Ti\u{FFFE}tle", 0.9),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative('desc', 'vector', 'proof', 'fix'),
            '$q',
        )->withReviewerValidation(true);

        $domDocument = $this->decodeJunit($this->makeReport($vulnerability));

        $testcase = $domDocument->getElementsByTagName('testcase')->item(0);
        self::assertNotNull($testcase);
        self::assertSame('BadTitle (src/Foo.php:1)', $testcase->getAttribute('name'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_drops_a_value_that_is_not_valid_utf8_instead_of_corrupting_the_document(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, "Bad\xC3Title", 0.9),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative('desc', 'vector', 'proof', 'fix'),
            '$q',
        )->withReviewerValidation(true);

        $domDocument = $this->decodeJunit($this->makeReport($vulnerability));

        $testcase = $domDocument->getElementsByTagName('testcase')->item(0);
        self::assertNotNull($testcase);
        self::assertSame(' (src/Foo.php:1)', $testcase->getAttribute('name'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
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
