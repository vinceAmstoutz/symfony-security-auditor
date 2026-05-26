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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\NullProgressReporter;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AuditPipeline implements PipelineInterface
{
    /** @var list<StageInterface> */
    private array $stages;

    private ProgressReporterInterface $progressReporter;

    /**
     * @param iterable<StageInterface> $stages
     */
    public function __construct(
        iterable $stages,
        private LoggerInterface $logger,
        ?ProgressReporterInterface $progressReporter = null,
    ) {
        $collected = [];
        foreach ($stages as $stage) {
            $collected[] = $stage;
        }

        $this->stages = $collected;
        $this->progressReporter = $progressReporter ?? new NullProgressReporter();
    }

    public function process(AuditContext $auditContext): void
    {
        $stageNames = array_map(static fn (StageInterface $stage): string => $stage->name(), $this->stages);

        $this->logger->info('Starting audit pipeline', [
            'audit_id' => $auditContext->auditId(),
            'stages' => $stageNames,
        ]);

        $this->progressReporter->report(ProgressEvent::PipelineStarted->value, [
            'audit_id' => $auditContext->auditId(),
            'stages' => $stageNames,
        ]);

        foreach ($this->stages as $stage) {
            $this->logger->info(\sprintf('Running stage: %s', $stage->name()), [
                'audit_id' => $auditContext->auditId(),
            ]);

            $this->progressReporter->report(ProgressEvent::StageStarted->value, [
                'audit_id' => $auditContext->auditId(),
                'stage' => $stage->name(),
            ]);

            $start = microtime(true);
            $stage->process($auditContext);
            $elapsed = microtime(true) - $start;

            $this->logger->info(\sprintf('Stage "%s" completed', $stage->name()), [
                'audit_id' => $auditContext->auditId(),
                'elapsed_seconds' => $elapsed,
            ]);

            $this->progressReporter->report(ProgressEvent::StageCompleted->value, [
                'audit_id' => $auditContext->auditId(),
                'stage' => $stage->name(),
                'elapsed_seconds' => $elapsed,
            ]);
        }

        $this->logger->info('Pipeline complete', [
            'audit_id' => $auditContext->auditId(),
            'vulnerabilities_found' => \count($auditContext->vulnerabilities()),
            'validated' => \count($auditContext->validatedVulnerabilities()),
        ]);

        $this->progressReporter->report(ProgressEvent::PipelineCompleted->value, [
            'audit_id' => $auditContext->auditId(),
            'vulnerabilities_found' => \count($auditContext->vulnerabilities()),
            'validated' => \count($auditContext->validatedVulnerabilities()),
        ]);
    }

    /** @return list<StageInterface> */
    public function stages(): array
    {
        return $this->stages;
    }
}
