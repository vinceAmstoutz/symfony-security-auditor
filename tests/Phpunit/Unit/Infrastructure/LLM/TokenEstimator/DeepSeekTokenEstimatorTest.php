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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\DeepSeekTokenEstimator;

final class DeepSeekTokenEstimatorTest extends TestCase
{
    public function test_it_supports_deepseek_models(): void
    {
        self::assertTrue((new DeepSeekTokenEstimator())->supports('deepseek-chat'));
    }

    public function test_it_does_not_support_a_non_deepseek_model(): void
    {
        self::assertFalse((new DeepSeekTokenEstimator())->supports('gpt-4o'));
    }

    public function test_it_applies_the_deepseek_ratio(): void
    {
        self::assertSame(30, (new DeepSeekTokenEstimator())->estimateTokens(str_repeat('x', 100), 'deepseek-chat'));
    }
}
