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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Config;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

final class StandaloneConfigLoaderTest extends TestCase
{
    private string $configHome;

    private Filesystem $filesystem;

    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configHome = sys_get_temp_dir().'/ssa-config-'.bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        $this->filesystem->remove($this->configHome);
    }

    public function test_it_normalizes_the_audit_settings_and_ignores_the_platform_keys(): void
    {
        $this->writeConfig("provider: anthropic\napi_key: sk-test\nmodel: gpt-5.4\n");

        self::assertSame('gpt-5.4', $this->loader()->load()->auditConfig['model']);
    }

    public function test_it_resolves_the_platform_connection(): void
    {
        $this->writeConfig("provider: anthropic\napi_key: sk-test\n");

        self::assertSame(['anthropic' => ['api_key' => 'sk-test']], $this->loader()->load()->platform->toAiPlatformConfig());
    }

    public function test_it_applies_audit_defaults_when_only_a_provider_is_configured(): void
    {
        $this->writeConfig("provider: ollama\nendpoint: http://localhost:11434\n");

        self::assertSame('claude-opus-4-8', $this->loader()->load()->auditConfig['model']);
    }

    public function test_it_rejects_a_config_without_a_provider(): void
    {
        $this->writeConfig("model: gpt-5.4\n");

        $this->expectException(MissingProviderException::class);

        $this->loader()->load();
    }

    public function test_it_rejects_a_missing_config_file(): void
    {
        $this->expectException(MissingProviderException::class);

        $this->loader()->load();
    }

    public function test_it_rejects_an_empty_config_file(): void
    {
        $this->writeConfig('');

        $this->expectException(MissingProviderException::class);

        $this->loader()->load();
    }

    private function loader(): StandaloneConfigLoader
    {
        return new StandaloneConfigLoader(
            new XdgConfigPathResolver($this->configHome, null, null),
            new AuditConfiguration(),
            new StandalonePlatformConfigResolver(),
        );
    }

    private function writeConfig(string $yaml): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $yaml);
    }
}
