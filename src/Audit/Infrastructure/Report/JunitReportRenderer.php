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
 * Renders an audit report as JUnit XML — one failed test case per validated
 * finding — for CI test-report panels such as GitLab merge-request widgets.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class JunitReportRenderer implements ReportRendererInterface
{
    /**
     * Complement of the XML 1.0 Char production: control characters other
     * than tab/CR/LF, UTF-16 surrogate halves, and the U+FFFE/U+FFFF
     * non-characters — all valid UTF-8, all rejected by XML parsers.
     */
    private const string ILLEGAL_XML_CHARACTERS = '/[^\x{9}\x{A}\x{D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]/u';

    #[Override]
    public function format(): string
    {
        return 'junit';
    }

    #[Override]
    public function render(AuditReport $auditReport): string
    {
        $vulnerabilities = $auditReport->vulnerabilities();

        $domDocument = new DOMDocument('1.0', 'UTF-8');
        $domDocument->formatOutput = true;

        $domElement = $domDocument->createElement('testsuites');
        $domDocument->appendChild($domElement);

        $testsuite = $domDocument->createElement('testsuite');
        $testsuite->setAttribute('name', 'symfony-security-auditor');
        $testsuite->setAttribute('tests', (string) \count($vulnerabilities));
        $testsuite->setAttribute('failures', (string) \count($vulnerabilities));

        $domElement->appendChild($testsuite);

        foreach ($vulnerabilities as $vulnerability) {
            $testsuite->appendChild($this->testCase($domDocument, $vulnerability));
        }

        return (string) $domDocument->saveXML();
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
            $vulnerability->type()->cweReference(),
            $this->stripIllegalXmlCharacters($vulnerability->remediation()),
        )));
        $domElement->appendChild($failure);

        return $domElement;
    }

    /**
     * DOMDocument::saveXML() writes illegal characters out verbatim without
     * escaping them — a finding whose LLM-produced text carries one silently
     * corrupts the document for any consumer that re-parses it. A value that
     * is not valid UTF-8 at all cannot be repaired and is dropped wholesale.
     */
    private function stripIllegalXmlCharacters(string $value): string
    {
        return preg_replace(self::ILLEGAL_XML_CHARACTERS, '', $value) ?? '';
    }
}
