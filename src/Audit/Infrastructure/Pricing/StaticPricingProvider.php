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

    /**
     * @var array<string, array{0: float, 1: float}> input/output USD per million tokens
     *
     * Standard paid-tier list prices for the text models of every commercial
     * platform shipped by symfony/ai. Self-hosted/local platforms (Ollama,
     * LM Studio, Docker Model Runner, TransformersPHP) bill no per-token cost and
     * are intentionally absent. Models with prompt-size tiers (Gemini *-pro,
     * GPT-5.x) are listed at their base / short-prompt tier; very large prompts
     * cost more. Unknown models resolve to 0.0 (cost reporting disabled), never
     * an error.
     *
     * Sources, last updated 2026-05-29:
     * - Anthropic: https://platform.claude.com/docs/en/about-claude/models/overview
     * - OpenAI:    https://platform.openai.com/docs/pricing
     * - Google:    https://ai.google.dev/gemini-api/docs/pricing
     * - Mistral:   https://mistral.ai/pricing
     * - Cohere:    https://cohere.com/pricing
     * - DeepSeek:  https://api-docs.deepseek.com/quick_start/pricing
     * - Perplexity: https://docs.perplexity.ai/getting-started/pricing
     * - Cerebras:  https://www.cerebras.ai/pricing
     */
    private const array PRICES = [
        // Anthropic Claude — current
        'claude-opus-4-8' => [5.00, 25.00],
        'claude-sonnet-4-6' => [3.00, 15.00],
        'claude-haiku-4-5-20251001' => [1.00, 5.00],
        // Anthropic Claude — legacy (kept for cost reporting on existing configs)
        'claude-haiku-4-5' => [1.00, 5.00],
        'claude-opus-4-7' => [5.00, 25.00],
        'claude-opus-4-6' => [5.00, 25.00],
        'claude-opus-4-5-20251101' => [5.00, 25.00],
        'claude-opus-4-5' => [5.00, 25.00],
        'claude-sonnet-4-5-20250929' => [3.00, 15.00],
        'claude-sonnet-4-5' => [3.00, 15.00],
        'claude-opus-4-1-20250805' => [15.00, 75.00],
        'claude-opus-4-1' => [15.00, 75.00],
        'claude-opus-4-20250514' => [15.00, 75.00],
        'claude-opus-4' => [15.00, 75.00],
        'claude-opus-4-0' => [15.00, 75.00],
        'claude-sonnet-4-20250514' => [3.00, 15.00],
        'claude-sonnet-4' => [3.00, 15.00],
        'claude-sonnet-4-0' => [3.00, 15.00],
        // OpenAI
        'gpt-5.5-pro' => [30.00, 180.00],
        'gpt-5.5' => [5.00, 30.00],
        'gpt-5.4-pro' => [30.00, 180.00],
        'gpt-5.4' => [2.50, 15.00],
        'gpt-5.4-mini' => [0.75, 4.50],
        'gpt-5.4-nano' => [0.20, 1.25],
        'gpt-5-mini' => [0.25, 2.00],
        'gpt-5-nano' => [0.05, 0.40],
        'gpt-4.1' => [2.00, 8.00],
        'gpt-4.1-mini' => [0.40, 1.60],
        'gpt-4.1-nano' => [0.10, 0.40],
        'gpt-4o' => [2.50, 10.00],
        'gpt-4o-mini' => [0.15, 0.60],
        'o3' => [2.00, 8.00],
        'o4-mini' => [0.55, 2.20],
        // Google Gemini (base tier for prompt-size-tiered models)
        'gemini-3.5-flash' => [1.50, 9.00],
        'gemini-3.1-pro-preview' => [2.00, 12.00],
        'gemini-3.1-flash-lite' => [0.25, 1.50],
        'gemini-3-flash-preview' => [0.50, 3.00],
        'gemini-2.5-pro' => [1.25, 10.00],
        'gemini-2.5-flash' => [0.30, 2.50],
        'gemini-2.5-flash-lite' => [0.10, 0.40],
        'gemini-2.0-flash' => [0.10, 0.40],
        // Mistral AI
        'mistral-large-latest' => [0.50, 1.50],
        'mistral-large-2512' => [0.50, 1.50],
        'mistral-medium-latest' => [1.50, 7.50],
        'mistral-medium-2604' => [1.50, 7.50],
        'mistral-small-latest' => [0.15, 0.60],
        'mistral-small-2603' => [0.15, 0.60],
        'codestral-latest' => [0.30, 0.90],
        'codestral-2508' => [0.30, 0.90],
        'devstral-medium-2512' => [0.40, 2.00],
        'devstral-small-2512' => [0.10, 0.30],
        'ministral-3b-2512' => [0.10, 0.10],
        'ministral-8b-2512' => [0.15, 0.15],
        'ministral-14b-2512' => [0.20, 0.20],
        // Cohere
        'command-a-03-2025' => [2.50, 10.00],
        'command-r-plus-08-2024' => [2.50, 10.00],
        'command-r-08-2024' => [0.15, 0.60],
        'command-r7b-12-2024' => [0.0375, 0.15],
        // DeepSeek
        'deepseek-chat' => [0.14, 0.28],
        'deepseek-reasoner' => [0.14, 0.28],
        'deepseek-v4-flash' => [0.14, 0.28],
        'deepseek-v4-pro' => [1.74, 3.48],
        // Perplexity (per-token only; sonar models also bill a per-request search fee)
        'sonar' => [1.00, 1.00],
        'sonar-pro' => [3.00, 15.00],
        'sonar-reasoning-pro' => [2.00, 8.00],
        // Cerebras
        'gpt-oss-120b' => [0.35, 0.75],
        'zai-glm-4.7' => [2.25, 2.75],
    ];

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
