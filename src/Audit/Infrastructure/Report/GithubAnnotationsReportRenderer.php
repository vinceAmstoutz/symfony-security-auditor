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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;

use function Symfony\Component\String\u;

/**
 * Renders an audit report as GitHub Actions workflow-command annotations — one
 * `::error`/`::warning`/`::notice` line per validated finding — so findings
 * appear inline on the PR's "Files changed" view without a separate SARIF
 * upload step.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class GithubAnnotationsReportRenderer implements ReportRendererInterface
{
    #[Override]
    public function format(): string
    {
        return 'github';
    }

    #[Override]
    public function render(AuditReport $auditReport): string
    {
        return implode("\n", array_map(
            $this->annotation(...),
            $auditReport->vulnerabilities(),
        ));
    }

    private function annotation(Vulnerability $vulnerability): string
    {
        return \sprintf(
            '::%s %s::%s',
            $this->annotationLevel($vulnerability->severity()),
            $this->properties($vulnerability),
            $this->escapeData($this->message($vulnerability)),
        );
    }

    private function annotationLevel(VulnerabilitySeverity $vulnerabilitySeverity): string
    {
        return SeverityLevelMapper::level($vulnerabilitySeverity, 'notice');
    }

    private function properties(Vulnerability $vulnerability): string
    {
        $properties = [
            'file' => $this->escapeProperty($vulnerability->filePath()),
            'line' => $vulnerability->lineStart(),
        ];

        if ($vulnerability->lineEnd() !== $vulnerability->lineStart()) {
            $properties['endLine'] = $vulnerability->lineEnd();
        }

        $properties['title'] = $this->escapeProperty($vulnerability->title());

        $pairs = [];
        foreach ($properties as $name => $value) {
            $pairs[] = \sprintf('%s=%s', $name, $value);
        }

        return implode(',', $pairs);
    }

    private function message(Vulnerability $vulnerability): string
    {
        return \sprintf(
            "%s\n\nRemediation: %s",
            $vulnerability->description(),
            $vulnerability->remediation(),
        );
    }

    private function escapeData(string $value): string
    {
        $encoded = u(mb_scrub($value, 'UTF-8'))
            ->replace('%', '%25')
            ->replace("\r\n", '%0D%0A')
            ->replace("\r", '%0D')
            ->replace("\n", '%0A')
            ->toString();

        return TerminalTextSanitizer::stripControlCharacters($encoded);
    }

    private function escapeProperty(string $value): string
    {
        return u($this->escapeData($value))
            ->replace(':', '%3A')
            ->replace(',', '%2C')
            ->toString();
    }
}
