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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ResolvingTokenEstimator implements TokenEstimatorInterface
{
    public const float CHARS_PER_TOKEN_DEFAULT = 3.2;

    /** @param iterable<ProviderTokenEstimatorInterface> $providerEstimators first whose supports() matches the model wins */
    public function __construct(
        private iterable $providerEstimators = [
            new AnthropicTokenEstimator(),
            new OpenAiTokenEstimator(),
            new GeminiTokenEstimator(),
            new MistralTokenEstimator(),
            new LlamaTokenEstimator(),
            new DeepSeekTokenEstimator(),
        ],
        private CharacterRatioCounter $characterRatioCounter = new CharacterRatioCounter(),
        private float $fallbackCharsPerToken = self::CHARS_PER_TOKEN_DEFAULT,
    ) {}

    public function estimateTokens(string $text, string $model): int
    {
        foreach ($this->providerEstimators as $providerEstimator) {
            if ($providerEstimator->supports($model)) {
                return $providerEstimator->estimateTokens($text, $model);
            }
        }

        return $this->characterRatioCounter->estimate($text, $this->fallbackCharsPerToken);
    }
}
