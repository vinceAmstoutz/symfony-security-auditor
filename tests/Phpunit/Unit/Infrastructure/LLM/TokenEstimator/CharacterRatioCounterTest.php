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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\TokenEstimator;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\CharacterRatioCounter;

final class CharacterRatioCounterTest extends TestCase
{
    public function test_empty_string_returns_zero_tokens(): void
    {
        self::assertSame(0, (new CharacterRatioCounter())->estimate('', 3.5));
    }

    public function test_multibyte_characters_each_count_as_one_character_not_one_byte(): void
    {
        self::assertSame(3, (new CharacterRatioCounter())->estimate(str_repeat('€', 10), 3.5));
    }

    public function test_fractional_token_counts_round_up_to_the_next_whole_token(): void
    {
        self::assertSame(3, (new CharacterRatioCounter())->estimate(str_repeat('x', 8), 3.5));
    }

    public function test_character_count_is_divided_by_the_ratio_not_multiplied(): void
    {
        self::assertSame(25, (new CharacterRatioCounter())->estimate(str_repeat('x', 100), 4.0));
    }
}
