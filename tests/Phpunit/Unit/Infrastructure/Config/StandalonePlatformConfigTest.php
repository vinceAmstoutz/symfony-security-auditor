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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;

final class StandalonePlatformConfigTest extends TestCase
{
    public function test_it_names_the_credential_the_run_authenticates_with(): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['anthropic' => ['api_key' => 'anthropic-test-key-for-previews']]);

        self::assertSame('anthro…iews', $standalonePlatformConfig->credentialIdentity()?->maskedPreview);
    }

    public function test_it_names_the_credential_the_container_reads_rather_than_its_escaped_spelling(): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['anthropic' => ['api_key' => 'anthropic-test-key-50%%%%']]);

        self::assertSame(CredentialIdentity::of('anthropic-test-key-50%%')->fingerprint, $standalonePlatformConfig->credentialIdentity()?->fingerprint);
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

    public function test_it_names_the_credential_of_the_provider_the_run_selects(): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(
            ['anthropic' => ['api_key' => 'anthropic-test-key-for-previews'], 'openai' => ['api_key' => 'openai-test-key-for-previews-2']],
            'openai',
        );

        self::assertSame('openai…ws-2', $standalonePlatformConfig->credentialIdentity()?->maskedPreview);
    }

    public function test_it_names_the_credential_of_the_selected_instance(): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(
            ['generic' => ['a' => ['api_key' => 'generic-test-key-instance-a-000'], 'b' => ['api_key' => 'generic-test-key-instance-b-111']]],
            'generic.b',
        );

        self::assertSame('generi…-111', $standalonePlatformConfig->credentialIdentity()?->maskedPreview);
    }

    public function test_it_names_no_credential_when_the_selected_provider_is_not_configured(): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['anthropic' => ['api_key' => 'anthropic-test-key-for-previews']], 'mistral');

        self::assertNull($standalonePlatformConfig->credentialIdentity());
    }
}
