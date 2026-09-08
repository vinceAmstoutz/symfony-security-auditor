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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Port;

/**
 * Resolves per-million-token USD pricing for a given LLM model identifier,
 * including prompt-cache traffic.
 *
 * Implementations may consult a hardcoded table, a configuration file, or an
 * external pricing service. Unknown models should return `0.0` rather than
 * throw — the audit pipeline keeps running with cost tracking disabled.
 *
 * A provider whose models carry no published cache rate should return
 * {@see self::pricePerMillionInputTokens()} from both cache methods, so cache
 * traffic is never under-priced relative to plain input.
 */
interface PricingProviderInterface
{
    public function pricePerMillionInputTokens(string $model): float;

    public function pricePerMillionOutputTokens(string $model): float;

    public function cacheReadPricePerMillionTokens(string $model): float;

    public function cacheCreationPricePerMillionTokens(string $model): float;

    public function hasModel(string $model): bool;
}
