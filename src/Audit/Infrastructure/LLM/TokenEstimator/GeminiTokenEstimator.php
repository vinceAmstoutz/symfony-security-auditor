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

use Override;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class GeminiTokenEstimator implements ProviderTokenEstimatorInterface
{
    public const float CHARS_PER_TOKEN = 3.8;

    public function __construct(private CharacterRatioCounter $characterRatioCounter = new CharacterRatioCounter()) {}

    #[Override]
    public function supports(string $model): bool
    {
        return u($model)->startsWith('gemini-');
    }

    #[Override]
    public function estimateTokens(string $text, string $model): int
    {
        return $this->characterRatioCounter->estimate($text, self::CHARS_PER_TOKEN);
    }
}
