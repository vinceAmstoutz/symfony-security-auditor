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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CliAgentPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;

final class CliAgentPlatformsTest extends TestCase
{
    public function test_a_run_on_a_cli_turns_the_auditor_tools_off_and_keeps_every_other_setting(): void
    {
        self::assertSame(
            [
                'model' => 'sonnet',
                'audit' => [
                    'max_iterations' => 2,
                    'tools_enabled' => false,
                    'structured_collection' => false,
                    'reviewer_tools_enabled' => false,
                    'reviewer_structured_collection' => false,
                ],
            ],
            CliAgentPlatforms::auditConfigFor(['model' => 'sonnet', 'audit' => ['max_iterations' => 2, 'tools_enabled' => true]], new StandalonePlatformConfig(['claudecode' => []], 'claudecode')),
        );
    }

    public function test_a_run_on_an_api_platform_keeps_its_audit_settings(): void
    {
        $auditConfig = ['audit' => ['tools_enabled' => true]];

        self::assertSame($auditConfig, CliAgentPlatforms::auditConfigFor($auditConfig, new StandalonePlatformConfig(['anthropic' => []], 'anthropic')));
    }

    public function test_a_run_that_selects_no_provider_keeps_its_audit_settings(): void
    {
        $auditConfig = ['audit' => ['tools_enabled' => true]];

        self::assertSame($auditConfig, CliAgentPlatforms::auditConfigFor($auditConfig, new StandalonePlatformConfig(['claudecode' => []])));
    }
}
