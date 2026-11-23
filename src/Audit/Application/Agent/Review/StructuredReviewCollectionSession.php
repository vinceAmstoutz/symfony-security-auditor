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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordingToolReach;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Wires a fresh collector into a `record_review` registry for one
 * structured-collection round and drains what the LLM recorded back into raw
 * verdict payloads.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class StructuredReviewCollectionSession
{
    private function __construct(
        private ReviewCollector $reviewCollector,
        public ToolRegistry $toolRegistry,
        private RecordingToolReach $recordingToolReach,
    ) {}

    /**
     * @throws InvalidToolRegistryException
     */
    public static function begin(RecordReviewToolFactoryInterface $recordReviewToolFactory, LoggerInterface $logger): self
    {
        $reviewCollector = new ReviewCollector();
        $recordingToolReach = new RecordingToolReach();
        $toolRegistry = new ToolRegistry([$recordingToolReach->track($recordReviewToolFactory->create($reviewCollector))], $logger);

        $recordingToolReach->handOver();

        return new self($reviewCollector, $toolRegistry, $recordingToolReach);
    }

    /**
     * Tells whether the client offered the recording tool to the model or
     * called it. When it did neither, the answer text is all the model said.
     */
    public function recordingToolReached(): bool
    {
        return $this->recordingToolReach->reached();
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function drain(): array
    {
        return $this->reviewCollector->drain();
    }
}
