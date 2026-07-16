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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\MiniMaxTokenEstimator;

final class MiniMaxTokenEstimatorTest extends TestCase
{
    public function test_it_supports_official_mixed_case_minimax_models(): void
    {
        self::assertTrue((new MiniMaxTokenEstimator())->supports('MiniMax-M2'));
    }

    public function test_it_supports_lowercase_minimax_models(): void
    {
        self::assertTrue((new MiniMaxTokenEstimator())->supports('minimax-m2.1'));
    }

    public function test_it_does_not_support_a_non_minimax_model(): void
    {
        self::assertFalse((new MiniMaxTokenEstimator())->supports('gpt-4o'));
    }

    public function test_it_applies_the_minimax_ratio(): void
    {
        self::assertSame(29, (new MiniMaxTokenEstimator())->estimateTokens(str_repeat('x', 100), 'MiniMax-M2'));
    }
}
