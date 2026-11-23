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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;

/**
 * Wraps the optional {@see ReviewerCacheInterface}: a missing cache or a
 * bypassed run misses every lookup. Never stores a verdict that judges
 * nothing (none, or no `accepted` flag) or one given at the tool-call limit.
 * Logs a store failure instead of propagating it.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReviewerVerdictCache
{
    public function __construct(
        private ?ReviewerCacheInterface $reviewerCache,
        private LoggerInterface $logger,
    ) {}

    /**
     * Returns the code context to cache the answer's verdicts under, null for
     * an answer given at the tool-call limit.
     */
    public static function contextFor(LLMResponse $llmResponse, ?string $codeContext): ?string
    {
        return $llmResponse->reachedToolCap() ? null : $codeContext;
    }

    /**
     * @param array<string, string> $codeContexts
     *
     * @return array<string, string>
     */
    public static function contextsFor(LLMResponse $llmResponse, array $codeContexts): array
    {
        return $llmResponse->reachedToolCap() ? [] : $codeContexts;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function get(Vulnerability $vulnerability, string $codeContext, bool $bypassCache): ?array
    {
        if ($bypassCache || !$this->reviewerCache instanceof ReviewerCacheInterface) {
            return null;
        }

        $cached = $this->reviewerCache->get($vulnerability, $codeContext);
        if (!$this->judges($cached)) {
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
        if (!$this->judges($verdict) || !$this->reviewerCache instanceof ReviewerCacheInterface) {
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

    /**
     * @param array<string, mixed>|null $verdict
     *
     * @phpstan-assert-if-true array<string, mixed> $verdict
     */
    private function judges(?array $verdict): bool
    {
        return null !== AcceptedFlag::read($verdict['accepted'] ?? null);
    }
}
