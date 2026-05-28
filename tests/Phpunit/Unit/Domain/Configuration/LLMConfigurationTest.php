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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Configuration;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\LLMConfiguration;

final class LLMConfigurationTest extends TestCase
{
    public function test_provider_json_mode_defaults_to_off(): void
    {
        $lLMConfiguration = new LLMConfiguration('claude-opus-4-7', null, null);

        self::assertFalse($lLMConfiguration->providerJsonMode);
    }

    public function test_agent_models_fall_back_to_the_shared_model_when_no_override_is_set(): void
    {
        $lLMConfiguration = new LLMConfiguration('shared-model', null, null);

        self::assertSame('shared-model', $lLMConfiguration->attackerModel());
        self::assertSame('shared-model', $lLMConfiguration->reviewerModel());
    }

    public function test_agent_model_overrides_take_precedence_over_the_shared_model(): void
    {
        $lLMConfiguration = new LLMConfiguration('shared-model', 'attacker-override', 'reviewer-override');

        self::assertSame('attacker-override', $lLMConfiguration->attackerModel());
        self::assertSame('reviewer-override', $lLMConfiguration->reviewerModel());
    }

    public function test_agent_max_output_tokens_fall_back_to_the_shared_cap_when_no_override_is_set(): void
    {
        $lLMConfiguration = new LLMConfiguration('m', null, null, 4096);

        self::assertSame(4096, $lLMConfiguration->attackerMaxOutputTokens());
        self::assertSame(4096, $lLMConfiguration->reviewerMaxOutputTokens());
    }

    public function test_max_output_tokens_defaults_to_4096_when_omitted_at_construction(): void
    {
        $lLMConfiguration = new LLMConfiguration('m', null, null);

        self::assertSame(4096, $lLMConfiguration->attackerMaxOutputTokens());
        self::assertSame(4096, $lLMConfiguration->reviewerMaxOutputTokens());
    }

    public function test_agent_max_output_tokens_overrides_take_precedence_over_the_shared_cap(): void
    {
        $lLMConfiguration = new LLMConfiguration('m', null, null, 4096, 8192, 2048);

        self::assertSame(8192, $lLMConfiguration->attackerMaxOutputTokens());
        self::assertSame(2048, $lLMConfiguration->reviewerMaxOutputTokens());
    }
}
