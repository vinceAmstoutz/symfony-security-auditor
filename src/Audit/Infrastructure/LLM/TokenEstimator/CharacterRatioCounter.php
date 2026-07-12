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
 * BPE tokenizers operate on UTF-8 bytes, not characters, so `charsPerToken`
 * ratios only hold when a character is roughly one byte — true for ASCII/
 * Latin scripts, false for CJK and emoji, where a character can be 3-4
 * bytes. Counting bytes instead of characters keeps the ratio's assumption
 * valid across scripts with no per-script detection, and is a no-op for the
 * common ASCII case.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CharacterRatioCounter
{
    public function estimate(string $text, float $charsPerToken): int
    {
        return (int) ceil(\strlen($text) / $charsPerToken);
    }
}
