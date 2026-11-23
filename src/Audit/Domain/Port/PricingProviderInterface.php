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
 * USD per million tokens of an LLM model. Implementations SHOULD return `0.0`
 * for an unknown model rather than throw.
 */
interface PricingProviderInterface
{
    public function pricePerMillionInputTokens(string $model): float;

    public function pricePerMillionOutputTokens(string $model): float;

    public function hasModel(string $model): bool;
}
