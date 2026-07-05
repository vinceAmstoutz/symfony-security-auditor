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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * One structured-collection round: a fresh collector wired into a single-tool
 * `record_review` registry, and the drain step that turns whatever the LLM
 * recorded during the call back into raw verdict payloads. Shared by the
 * single-finding, concurrent, and batched structured review analyzers so the
 * wiring lives in one place.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StructuredReviewCollectionSession
{
    private function __construct(
        private ReviewCollector $reviewCollector,
        public ToolRegistry $toolRegistry,
    ) {}

    public static function begin(RecordReviewToolFactoryInterface $recordReviewToolFactory, LoggerInterface $logger): self
    {
        $reviewCollector = new ReviewCollector();

        return new self($reviewCollector, new ToolRegistry([$recordReviewToolFactory->create($reviewCollector)], $logger));
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function drain(): array
    {
        return $this->reviewCollector->drain();
    }
}
