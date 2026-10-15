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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use WeakMap;

/**
 * The LLM clients that have reached the recording tool during the run — read
 * its definition to offer it to the model, or called it — so a client that
 * builds the tool schemas once and keeps them still counts as offering the
 * tool on every later turn, though those turns read no definition. A client
 * that never did ignores the tools: the first turn that finds so warns once,
 * naming the setting that turns structured collection off for it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RecordingToolClients
{
    /** @var WeakMap<LLMClientInterface, true> */
    private WeakMap $reached;

    /** @var WeakMap<LLMClientInterface, true> */
    private WeakMap $warned;

    private function __construct(
        private LoggerInterface $logger,
        private string $recordingTool,
        private string $structuredCollectionSetting,
    ) {
        $this->reached = new WeakMap();
        $this->warned = new WeakMap();
    }

    public static function forAttacker(LoggerInterface $logger): self
    {
        return new self($logger, 'record_vulnerability', 'audit.structured_collection');
    }

    public static function forReviewer(LoggerInterface $logger): self
    {
        return new self($logger, 'record_review', 'audit.reviewer_structured_collection');
    }

    public function note(LLMClientInterface $llmClient, bool $reachedThisTurn): void
    {
        if ($reachedThisTurn) {
            $this->reached[$llmClient] = true;
        }
    }

    public function ignoresTools(LLMClientInterface $llmClient): bool
    {
        if ($this->reached[$llmClient] ?? false) {
            return false;
        }

        $this->warnOnce($llmClient);

        return true;
    }

    private function warnOnce(LLMClientInterface $llmClient): void
    {
        if ($this->warned[$llmClient] ?? false) {
            return;
        }

        $this->warned[$llmClient] = true;
        $this->logger->warning(\sprintf('The LLM client never offered the %s tool to the model, so its answers are read as JSON; set %s: false for a client that ignores tools.', $this->recordingTool, $this->structuredCollectionSetting));
    }
}
