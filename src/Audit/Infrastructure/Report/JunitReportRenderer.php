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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * Renders an audit report as JUnit XML — one failed test case per validated
 * finding — for CI test-report panels such as GitLab merge-request widgets.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class JunitReportRenderer
{
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
        $domElement = $domDocument->createElement('testcase');
        $domElement->setAttribute('classname', $vulnerability->type()->value);
        $domElement->setAttribute('name', \sprintf(
            '%s (%s:%d)',
            $vulnerability->title(),
            $vulnerability->filePath(),
            $vulnerability->lineStart(),
        ));

        $failure = $domDocument->createElement('failure');
        $failure->setAttribute('type', $vulnerability->severity()->value);
        $failure->setAttribute('message', $vulnerability->title());
        $failure->appendChild($domDocument->createTextNode(\sprintf(
            "%s\n\nSeverity: %s\nLocation: %s:%d-%d\nOWASP: %s\nRemediation: %s",
            $vulnerability->description(),
            $vulnerability->severity()->value,
            $vulnerability->filePath(),
            $vulnerability->lineStart(),
            $vulnerability->lineEnd(),
            $vulnerability->type()->owaspReference(),
            $vulnerability->remediation(),
        )));
        $domElement->appendChild($failure);

        return $domElement;
    }
}
