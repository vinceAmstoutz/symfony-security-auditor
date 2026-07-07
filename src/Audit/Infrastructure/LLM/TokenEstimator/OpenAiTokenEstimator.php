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
final readonly class OpenAiTokenEstimator implements ProviderTokenEstimatorInterface
{
    public const float CHARS_PER_TOKEN = 4.0;

    /** @var list<string> */
    private const array PREFIXES = ['gpt-', 'o1', 'o3', 'o4'];

    public function __construct(private CharacterRatioCounter $characterRatioCounter = new CharacterRatioCounter()) {}

    #[Override]
    public function supports(string $model): bool
    {
        foreach (self::PREFIXES as $prefix) {
            if (u($model)->startsWith($prefix)) {
                return true;
            }
        }

        return false;
    }

    #[Override]
    public function estimateTokens(string $text, string $model): int
    {
        return $this->characterRatioCounter->estimate($text, self::CHARS_PER_TOKEN);
    }
}
