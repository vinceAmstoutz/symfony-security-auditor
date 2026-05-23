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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;

/**
 * Coarse `ceil(strlen / charsPerToken)` estimator with per-model adjustments.
 *
 * Claude tokenizers average ~3.5 chars/token on English+code; GPT-4o averages
 * ~4. Gemini hovers around 4 as well. The constants are intentionally
 * conservative (smaller divisor → larger estimate) so dry-run reports lean
 * pessimistic for cost forecasting.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CharacterBasedTokenEstimator implements TokenEstimatorInterface
{
    public const float CHARS_PER_TOKEN_CLAUDE = 3.5;

    public const float CHARS_PER_TOKEN_GPT = 4.0;

    public const float CHARS_PER_TOKEN_GEMINI = 4.0;

    public const float CHARS_PER_TOKEN_DEFAULT = 3.5;

    public function estimateTokens(string $text, string $model): int
    {
        $charsPerToken = $this->charsPerToken($model);
        $length = mb_strlen($text);
        if (0 === $length) {
            return 0;
        }

        return (int) ceil($length / $charsPerToken);
    }

    private function charsPerToken(string $model): float
    {
        return match (true) {
            str_starts_with($model, 'claude-') => self::CHARS_PER_TOKEN_CLAUDE,
            str_starts_with($model, 'gpt-'), str_starts_with($model, 'o3'), str_starts_with($model, 'o4') => self::CHARS_PER_TOKEN_GPT,
            str_starts_with($model, 'gemini-') => self::CHARS_PER_TOKEN_GEMINI,
            default => self::CHARS_PER_TOKEN_DEFAULT,
        };
    }
}
