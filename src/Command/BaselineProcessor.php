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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/**
 * Generates and applies the accepted-finding baseline: resolves the effective
 * baseline path (CLI override before the configured default), persists or loads
 * fingerprints via the {@see BaselineInterface}, and filters the report.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BaselineProcessor implements BaselineProcessorInterface
{
    public function __construct(
        private BaselineInterface $baseline,
        private ?string $configuredBaseline = null,
    ) {}

    #[Override]
    public function generate(AuditReport $auditReport, string $path): int
    {
        $fingerprints = $auditReport->fingerprints();
        $this->baseline->save($path, $fingerprints);

        return \count($fingerprints);
    }

    #[Override]
    public function apply(AuditReport $auditReport, ?string $cliBaseline): BaselineResult
    {
        $baselinePath = $cliBaseline ?? $this->configuredBaseline;
        if (null === $baselinePath) {
            return new BaselineResult($auditReport, 0);
        }

        $before = $auditReport->totalVulnerabilities();
        $filtered = $auditReport->withoutFingerprints($this->baseline->load($baselinePath));

        return new BaselineResult($filtered, $before - $filtered->totalVulnerabilities());
    }
}
