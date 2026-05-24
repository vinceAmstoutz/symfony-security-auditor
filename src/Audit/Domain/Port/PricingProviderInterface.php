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
 * Resolves per-million-token USD pricing for a given LLM model identifier.
 *
 * Implementations may consult a hardcoded table, a configuration file, or an
 * external pricing service. Unknown models should return `0.0` rather than
 * throw — the audit pipeline keeps running with cost tracking disabled.
 */
interface PricingProviderInterface
{
    public function pricePerMillionInputTokens(string $model): float;

    public function pricePerMillionOutputTokens(string $model): float;

    public function hasModel(string $model): bool;
}
