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
     * XML 1.0 forbids every control character other than tab, CR and LF.
     *
     * @var list<string>
     */
    private const array ILLEGAL_XML_CHARACTERS = [
        "\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08",
        "\x0B", "\x0C",
        "\x0E", "\x0F", "\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17", "\x18", "\x19", "\x1A", "\x1B", "\x1C", "\x1D", "\x1E", "\x1F",
    ];

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

        $domElement = $domDocument->createElement('testcase');
        $domElement->setAttribute('classname', $vulnerability->type()->value);
        $domElement->setAttribute('name', \sprintf(
            '%s (%s:%d)',
            $title,
            $vulnerability->filePath(),
            $vulnerability->lineStart(),
        ));

        $failure = $domDocument->createElement('failure');
        $failure->setAttribute('type', $vulnerability->severity()->value);
        $failure->setAttribute('message', $title);
        $failure->appendChild($domDocument->createTextNode(\sprintf(
            "%s\n\nSeverity: %s\nLocation: %s:%d-%d\nOWASP: %s\nCWE: %s\nRemediation: %s",
            $this->stripIllegalXmlCharacters($vulnerability->description()),
            $vulnerability->severity()->value,
            $vulnerability->filePath(),
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
     * DOMDocument::saveXML() writes illegal control characters out verbatim
     * without escaping them — a finding whose LLM-produced text carries one
     * silently corrupts the document for any consumer that re-parses it.
     */
    private function stripIllegalXmlCharacters(string $value): string
    {
        return str_replace(self::ILLEGAL_XML_CHARACTERS, '', $value);
    }
}
