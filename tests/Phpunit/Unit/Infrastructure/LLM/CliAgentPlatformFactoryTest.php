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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Bridge\ClaudeCode\Factory as ClaudeCodeFactory;
use Symfony\AI\Platform\Bridge\Codex\Factory as CodexFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatformFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentWorkingDirectory;

final class CliAgentPlatformFactoryTest extends TestCase
{
    public function test_the_claude_code_platform_runs_a_full_claude_model_id(): void
    {
        $platform = CliAgentPlatformFactory::create(ClaudeCodeFactory::class, null, new CliAgentWorkingDirectory());

        self::assertSame('claude-opus-5-5', $platform->getModelCatalog()->getModel('claude-opus-5-5')->getName());
    }

    public function test_the_claude_code_platform_runs_a_claude_model_it_does_not_list(): void
    {
        $platform = CliAgentPlatformFactory::create(ClaudeCodeFactory::class, null, new CliAgentWorkingDirectory());

        self::assertSame('claude-opus-5', $platform->getModelCatalog()->getModel('claude-opus-5')->getName());
    }

    public function test_the_codex_platform_runs_a_gpt_model_its_bridge_does_not_list(): void
    {
        $platform = CliAgentPlatformFactory::create(CodexFactory::class, null, new CliAgentWorkingDirectory());

        self::assertSame('gpt-6.2-astra', $platform->getModelCatalog()->getModel('gpt-6.2-astra')->getName());
    }
}
