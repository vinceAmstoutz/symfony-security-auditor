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
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;

/**
 * Adapts the optional {@see ReviewerCacheInterface} for the review strategies:
 * a missing cache or a bypassed run degrades every lookup to a miss, and a
 * null verdict is never persisted. A store failure is caught and logged
 * rather than left to propagate — the caller already has the verdict in hand
 * by the time it stores it, so losing the cache write must never cost the
 * caller the verdict itself.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReviewerVerdictCache
{
    public function __construct(
        private ?ReviewerCacheInterface $reviewerCache,
        private LoggerInterface $logger,
    ) {}

    /**
     * @return array<string, mixed>|null
     */
    public function get(Vulnerability $vulnerability, string $codeContext, bool $bypassCache): ?array
    {
        if ($bypassCache || !$this->reviewerCache instanceof ReviewerCacheInterface) {
            return null;
        }

        $cached = $this->reviewerCache->get($vulnerability, $codeContext);
        if (null === $cached) {
            return null;
        }

        $this->logger->debug('Reviewer verdict served from cache', ['vulnerability_id' => $vulnerability->id()]);

        return $cached;
    }

    /**
     * @param array<string, mixed>|null $verdict
     */
    public function store(Vulnerability $vulnerability, string $codeContext, ?array $verdict): void
    {
        if (null === $verdict || !$this->reviewerCache instanceof ReviewerCacheInterface) {
            return;
        }

        try {
            $this->reviewerCache->store($vulnerability, $codeContext, $verdict);
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to store reviewer verdict in cache', [
                'vulnerability_id' => $vulnerability->id(),
                'error' => $throwable->getMessage(),
            ]);
        }
    }
}
