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

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class LlamaTokenEstimator implements ProviderTokenEstimatorInterface
{
    public const float CHARS_PER_TOKEN = 3.6;

    /** @var list<string> */
    private const array PREFIXES = ['llama-', 'llama3', 'llama4', 'meta-llama'];

    public function __construct(private CharacterRatioCounter $characterRatioCounter = new CharacterRatioCounter()) {}

    public function supports(string $model): bool
    {
        foreach (self::PREFIXES as $prefix) {
            if (u($model)->startsWith($prefix)) {
                return true;
            }
        }

        return false;
    }

    public function estimateTokens(string $text, string $model): int
    {
        return $this->characterRatioCounter->estimate($text, self::CHARS_PER_TOKEN);
    }
}
