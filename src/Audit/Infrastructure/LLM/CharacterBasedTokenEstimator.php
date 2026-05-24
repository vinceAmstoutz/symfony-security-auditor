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

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class CharacterBasedTokenEstimator implements TokenEstimatorInterface
{
    public const float CHARS_PER_TOKEN_CLAUDE = 3.5;

    public const float CHARS_PER_TOKEN_GPT = 4.0;

    public const float CHARS_PER_TOKEN_GEMINI = 3.8;

    public const float CHARS_PER_TOKEN_DEFAULT = 3.2;

    public function estimateTokens(string $text, string $model): int
    {
        return (int) ceil(mb_strlen($text) / $this->charsPerToken($model));
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
