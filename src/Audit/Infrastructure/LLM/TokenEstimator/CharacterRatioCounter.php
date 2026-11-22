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

/**
 * Applies a `charsPerToken` ratio to UTF-8 bytes, not characters: BPE
 * tokenizers work on bytes, where a CJK character or an emoji takes 3-4.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CharacterRatioCounter
{
    public function estimate(string $text, float $charsPerToken): int
    {
        return (int) ceil(\strlen($text) / $charsPerToken);
    }
}
