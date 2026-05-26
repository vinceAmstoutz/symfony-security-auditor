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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\HistoricalStatus;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AuditHistoryStoreInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Compares the current run's validated findings against the project's previous
 * audit (by fingerprint), tags each finding `New` or `StillPresent`, records a
 * `fixed` list (fingerprints present last time but gone now), then persists the
 * current fingerprint set for the next run.
 */
final readonly class HistoricalCorrelationStage implements StageInterface
{
    public function __construct(
        private AuditHistoryStoreInterface $auditHistoryStore,
        private LoggerInterface $logger,
        private bool $enabled = false,
    ) {}

    public function name(): string
    {
        return BuiltInStageName::HistoricalCorrelation->value;
    }

    public function process(AuditContext $auditContext): void
    {
        if (!$this->enabled) {
            $this->logger->debug('Historical correlation stage disabled, skipping');

            return;
        }

        $projectIdentifier = $auditContext->projectPath();
        $previousFingerprints = array_flip($this->auditHistoryStore->loadFingerprints($projectIdentifier));

        $newCount = 0;
        $stillPresentCount = 0;
        $currentFingerprints = [];

        foreach ($auditContext->validatedVulnerabilities() as $vulnerability) {
            $fingerprint = $vulnerability->fingerprint();
            $currentFingerprints[$fingerprint] = true;

            $status = isset($previousFingerprints[$fingerprint])
                ? HistoricalStatus::StillPresent
                : HistoricalStatus::New;

            if (HistoricalStatus::StillPresent === $status) {
                ++$stillPresentCount;
            } else {
                ++$newCount;
            }

            $auditContext->replaceVulnerability($vulnerability->withHistoricalStatus($status));
        }

        $fixedFingerprints = array_values(array_diff(
            array_keys($previousFingerprints),
            array_keys($currentFingerprints),
        ));

        $this->auditHistoryStore->storeFingerprints($projectIdentifier, array_keys($currentFingerprints));

        $auditContext->setMeta('audit.history.new', $newCount);
        $auditContext->setMeta('audit.history.still_present', $stillPresentCount);
        $auditContext->setMeta('audit.history.fixed', \count($fixedFingerprints));
        $auditContext->setMeta('audit.history.fixed_fingerprints', $fixedFingerprints);

        $this->logger->info('Historical correlation complete', [
            'new' => $newCount,
            'still_present' => $stillPresentCount,
            'fixed' => \count($fixedFingerprints),
        ]);
    }
}
