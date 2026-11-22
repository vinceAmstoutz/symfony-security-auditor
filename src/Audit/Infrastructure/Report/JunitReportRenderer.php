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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

use DOMDocument;
use DOMElement;
use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * Renders an audit report as JUnit XML, one failed test case per validated
 * finding. An incomplete audit adds an errored "Audit completeness" test case
 * naming the unanalyzed files, so a panel never reads it as a clean run.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class JunitReportRenderer implements ReportRendererInterface
{
    /**
     * Every character outside the XML 1.0 Char production.
     */
    private const string ILLEGAL_XML_CHARACTERS = '/[^\x{9}\x{A}\x{D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]/u';

    private const string SUITE_NAME = 'symfony-security-auditor';

    #[Override]
    public function format(): string
    {
        return 'junit';
    }

    #[Override]
    public function render(AuditReport $auditReport): string
    {
        $vulnerabilities = $auditReport->vulnerabilities();
        $notice = IncompleteAuditNotice::for($auditReport);
        $errors = null === $notice ? 0 : 1;

        $domDocument = new DOMDocument('1.0', 'UTF-8');
        $domDocument->formatOutput = true;

        $domElement = $domDocument->createElement('testsuites');
        $domDocument->appendChild($domElement);

        $testsuite = $domDocument->createElement('testsuite');
        $testsuite->setAttribute('name', self::SUITE_NAME);
        $testsuite->setAttribute('tests', (string) (\count($vulnerabilities) + $errors));
        $testsuite->setAttribute('failures', (string) \count($vulnerabilities));
        $testsuite->setAttribute('errors', (string) $errors);

        $domElement->appendChild($testsuite);

        if (null !== $notice) {
            $testsuite->appendChild($this->completenessTestCase($domDocument, $notice, $auditReport->unanalyzedFiles()));
        }

        foreach ($vulnerabilities as $vulnerability) {
            $testsuite->appendChild($this->testCase($domDocument, $vulnerability));
        }

        return (string) $domDocument->saveXML();
    }

    /**
     * @param list<string> $unanalyzedFiles
     */
    private function completenessTestCase(DOMDocument $domDocument, string $notice, array $unanalyzedFiles): DOMElement
    {
        $domElement = $domDocument->createElement('testcase');
        $domElement->setAttribute('classname', self::SUITE_NAME);
        $domElement->setAttribute('name', 'Audit completeness');

        $error = $domDocument->createElement('error');
        $error->setAttribute('type', 'incomplete');
        $error->setAttribute('message', $notice);
        $error->appendChild($domDocument->createTextNode(
            [] === $unanalyzedFiles
                ? $notice
                : implode("\n", ['Files not fully analyzed:', ...array_map($this->stripIllegalXmlCharacters(...), $unanalyzedFiles)]),
        ));
        $domElement->appendChild($error);

        return $domElement;
    }

    private function testCase(DOMDocument $domDocument, Vulnerability $vulnerability): DOMElement
    {
        $title = $this->stripIllegalXmlCharacters($vulnerability->title());
        $filePath = $this->stripIllegalXmlCharacters($vulnerability->filePath());

        $domElement = $domDocument->createElement('testcase');
        $domElement->setAttribute('classname', $vulnerability->type()->value);
        $domElement->setAttribute('name', \sprintf(
            '%s (%s:%d)',
            $title,
            $filePath,
            $vulnerability->lineStart(),
        ));

        $failure = $domDocument->createElement('failure');
        $failure->setAttribute('type', $vulnerability->severity()->value);
        $failure->setAttribute('message', $title);
        $failure->appendChild($domDocument->createTextNode(\sprintf(
            "%s\n\nSeverity: %s\nLocation: %s:%d-%d\nOWASP: %s\nCWE: %s\nRemediation: %s",
            $this->stripIllegalXmlCharacters($vulnerability->description()),
            $vulnerability->severity()->value,
            $filePath,
            $vulnerability->lineStart(),
            $vulnerability->lineEnd(),
            $vulnerability->type()->owaspReference(),
            $vulnerability->type()->cwe()->label(),
            $this->stripIllegalXmlCharacters($vulnerability->remediation()),
        )));
        $domElement->appendChild($failure);

        return $domElement;
    }

    /**
     * Strips control characters (bidirectional overrides included) and every
     * character XML forbids, which saveXML() would write out verbatim; a value
     * that is not valid UTF-8 becomes empty.
     */
    private function stripIllegalXmlCharacters(string $value): string
    {
        return preg_replace(self::ILLEGAL_XML_CHARACTERS, '', TerminalTextSanitizer::stripControlCharacters($value)) ?? '';
    }
}
