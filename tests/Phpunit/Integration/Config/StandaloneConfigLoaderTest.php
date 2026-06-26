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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
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

    public function test_it_passes_audit_settings_through_and_strips_the_platform_keys(): void
    {
        $this->writeConfig("provider: anthropic\nplatform:\n  anthropic:\n    api_key: sk-test\nmodel: gpt-5.4\n");

        self::assertSame(['model' => 'gpt-5.4'], $this->loader()->load()->auditConfig);
    }

    public function test_it_resolves_the_platform_connection(): void
    {
        $this->writeConfig("platform:\n  anthropic:\n    api_key: sk-test\n");

        self::assertSame(
            ['platform' => ['anthropic' => ['api_key' => 'sk-test']]],
            $this->loader()->load()->platform->toAiConfig(),
        );
    }

    public function test_it_leaves_the_audit_settings_empty_when_only_a_platform_is_configured(): void
    {
        $this->writeConfig("platform:\n  ollama:\n    endpoint: http://localhost:11434\n");

        self::assertSame([], $this->loader()->load()->auditConfig);
    }

    public function test_it_rejects_a_config_without_a_platform(): void
    {
        $this->writeConfig("model: gpt-5.4\n");

        $this->expectException(MissingPlatformException::class);

        $this->loader()->load();
    }

    public function test_it_rejects_a_missing_config_file(): void
    {
        $this->expectException(MissingPlatformException::class);

        $this->loader()->load();
    }

    public function test_it_rejects_an_empty_config_file(): void
    {
        $this->writeConfig('');

        $this->expectException(MissingPlatformException::class);

        $this->loader()->load();
    }

    private function loader(): StandaloneConfigLoader
    {
        return new StandaloneConfigLoader(
            new XdgConfigPathResolver($this->configHome, null, null),
            new StandalonePlatformConfigResolver(),
        );
    }

    private function writeConfig(string $yaml): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $yaml);
    }
}
