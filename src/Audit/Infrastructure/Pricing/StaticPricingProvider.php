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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final class StaticPricingProvider implements PricingProviderInterface
{
    /**
     * @var array<string, array{0: float, 1: float}> input/output USD per million tokens
     *
     * Prices sourced from https://platform.claude.com/docs/en/about-claude/models/overview
     * Last updated: 2026-05-24
     */
    private const array PRICES = [
        // Current models — https://platform.claude.com/docs/en/about-claude/models/overview
        'claude-opus-4-7' => [5.00, 25.00],
        'claude-sonnet-4-6' => [3.00, 15.00],
        'claude-haiku-4-5-20251001' => [1.00, 5.00],
        // Legacy models still available — kept for cost reporting on existing configs
        'claude-opus-4-6' => [5.00, 25.00],
        'claude-opus-4-5' => [5.00, 25.00],
        'claude-haiku-4-5' => [1.00, 5.00],   // alias for claude-haiku-4-5-20251001
        'claude-sonnet-4-5' => [3.00, 15.00],
        'claude-opus-4-1' => [15.00, 75.00],
        'claude-opus-4' => [15.00, 75.00],     // deprecated alias
        'claude-sonnet-4' => [3.00, 15.00],    // deprecated alias
        // Other providers
        'gpt-4o' => [2.50, 10.00],
        'gpt-4o-mini' => [0.15, 0.60],
        'gpt-4.1' => [2.00, 8.00],
        'o3' => [2.00, 8.00],
        'o4-mini' => [1.10, 4.40],
        'gemini-2.5-pro' => [1.25, 10.00],
        'gemini-2.0-flash' => [0.10, 0.40],
        'mistral-large' => [2.00, 6.00],
    ];

    /** @var array<string, true> */
    private array $warnedModels = [];

    public function __construct(private readonly LoggerInterface $logger) {}

    public function pricePerMillionInputTokens(string $model): float
    {
        if (!$this->hasModel($model)) {
            $this->warnUnknownModel($model);

            return 0.0;
        }

        return self::PRICES[$model][0];
    }

    public function pricePerMillionOutputTokens(string $model): float
    {
        if (!$this->hasModel($model)) {
            $this->warnUnknownModel($model);

            return 0.0;
        }

        return self::PRICES[$model][1];
    }

    public function hasModel(string $model): bool
    {
        return isset(self::PRICES[$model]);
    }

    private function warnUnknownModel(string $model): void
    {
        if (isset($this->warnedModels[$model])) {
            return;
        }

        $this->warnedModels[$model] = true;
        $this->logger->warning('No pricing entry for LLM model — cost reporting will show zero', [
            'model' => $model,
        ]);
    }
}
