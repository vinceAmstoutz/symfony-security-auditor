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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

/**
 * Test fake: a real StageInterface implementation that records every audit
 * context it processes. Used in unit tests of RunAuditUseCase to verify the
 * use case wires the pipeline against the audit context without resorting to
 * a mock of the (internal) PipelineInterface.
 */
final class RecordingStage implements StageInterface
{
    /** @var list<string> */
    public array $processedAuditIds = [];

    /** @var list<list<string>> */
    public array $observedScanPaths = [];

    public function name(): string
    {
        return 'recording';
    }

    public function process(AuditContext $auditContext): void
    {
        $this->processedAuditIds[] = $auditContext->auditId();
        $this->observedScanPaths[] = $auditContext->scanPaths();
    }
}
