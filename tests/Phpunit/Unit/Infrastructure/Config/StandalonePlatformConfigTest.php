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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;

final class StandalonePlatformConfigTest extends TestCase
{
    public function test_it_names_the_credential_the_run_authenticates_with(): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['anthropic' => ['api_key' => 'anthropic-test-key-for-previews']]);

        self::assertSame('anthro…iews', $standalonePlatformConfig->credentialIdentity()?->maskedPreview);
    }

    public function test_it_names_no_credential_for_a_provider_that_needs_none(): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['ollama' => ['host_url' => 'http://localhost:11434']]);

        self::assertNull($standalonePlatformConfig->credentialIdentity());
    }

    public function test_it_names_no_credential_for_a_run_told_it_needs_none(): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['anthropic' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL]]);

        self::assertNull($standalonePlatformConfig->credentialIdentity());
    }
}
