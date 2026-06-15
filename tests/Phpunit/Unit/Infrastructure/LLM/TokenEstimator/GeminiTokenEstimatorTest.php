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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\GeminiTokenEstimator;

final class GeminiTokenEstimatorTest extends TestCase
{
    public function test_it_supports_gemini_models(): void
    {
        self::assertTrue((new GeminiTokenEstimator())->supports('gemini-2.5-pro'));
    }

    public function test_it_does_not_support_a_non_gemini_model(): void
    {
        self::assertFalse((new GeminiTokenEstimator())->supports('gpt-4o'));
    }

    public function test_it_applies_the_gemini_ratio(): void
    {
        self::assertSame(27, (new GeminiTokenEstimator())->estimateTokens(str_repeat('x', 100), 'gemini-2.5-pro'));
    }
}
