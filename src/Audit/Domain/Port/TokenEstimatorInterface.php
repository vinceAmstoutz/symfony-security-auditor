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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

/**
 * Pre-flight token-count estimator for `--dry-run`.
 *
 * Estimates are coarse — typically a chars-per-token heuristic — and exist
 * only to let users gauge cost before paying for a real audit. Production
 * token counts come from `LLMResponse::inputTokens()` / `outputTokens()`.
 */
interface TokenEstimatorInterface
{
    public function estimateTokens(string $text, string $model): int;
}
