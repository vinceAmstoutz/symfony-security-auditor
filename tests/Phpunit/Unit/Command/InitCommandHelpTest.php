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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitCommandHelp;

final class InitCommandHelpTest extends TestCase
{
    public function test_it_names_the_model_default_that_no_provider_derives(): void
    {
        self::assertStringContainsString('claude-opus-4-8 — set it for any other provider, it is not derived from one', InitCommandHelp::HELP);
    }

    public function test_it_names_the_env_var_default_as_the_console_will_print_it(): void
    {
        self::assertStringContainsString('<PLATFORM>_API_KEY', InitCommandHelp::HELP);
        self::assertStringNotContainsString('&lt;', InitCommandHelp::HELP);
    }

    public function test_it_warns_that_a_base_url_is_the_origin_only(): void
    {
        self::assertStringContainsString('do not include a trailing <info>/v1</info>', InitCommandHelp::HELP);
    }

    public function test_it_shows_an_instance_keyed_invocation(): void
    {
        self::assertStringContainsString('--provider=generic.my_gateway --base-url=https://your-gateway.example', InitCommandHelp::HELP);
    }
}
