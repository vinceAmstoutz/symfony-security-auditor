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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

final readonly class AuditPipeline implements PipelineInterface
{
    /** @var list<StageInterface> */
    private array $stages;

    /**
     * @param iterable<StageInterface> $stages
     */
    public function __construct(
        iterable $stages,
        private LoggerInterface $logger,
    ) {
        $collected = [];
        foreach ($stages as $stage) {
            $collected[] = $stage;
        }

        $this->stages = $collected;
    }

    public function process(AuditContext $auditContext): void
    {
        $this->logger->info('Starting audit pipeline', [
            'audit_id' => $auditContext->auditId(),
            'stages' => array_map(static fn (StageInterface $stage): string => $stage->name(), $this->stages),
        ]);

        foreach ($this->stages as $stage) {
            $this->logger->info(\sprintf('Running stage: %s', $stage->name()), [
                'audit_id' => $auditContext->auditId(),
            ]);

            $start = microtime(true);
            $stage->process($auditContext);
            $elapsed = microtime(true) - $start;

            $this->logger->info(\sprintf('Stage "%s" completed', $stage->name()), [
                'audit_id' => $auditContext->auditId(),
                'elapsed_seconds' => $elapsed,
            ]);
        }

        $this->logger->info('Pipeline complete', [
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
