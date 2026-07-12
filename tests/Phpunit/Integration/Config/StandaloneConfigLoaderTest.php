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

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

final class StandaloneConfigLoaderTest extends TestCase
{
    private string $configHome;

    private Filesystem $filesystem;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configHome = sys_get_temp_dir().'/ssa-config-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->configHome);
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_it_passes_audit_settings_through_and_strips_the_platform_keys(): void
    {
        $this->writeConfig("provider: anthropic\nplatform:\n  anthropic:\n    api_key: sk-test\nmodel: gpt-5.4\n");

        self::assertSame(['model' => 'gpt-5.4'], $this->loader()->load()->auditConfig);
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_it_resolves_the_platform_connection(): void
    {
        $this->writeConfig("platform:\n  anthropic:\n    api_key: sk-test\n");

        self::assertSame(
            ['platform' => ['anthropic' => ['api_key' => 'sk-test']]],
            $this->loader()->load()->platform->toAiConfig(),
        );
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_it_leaves_the_audit_settings_empty_when_only_a_platform_is_configured(): void
    {
        $this->writeConfig("platform:\n  ollama:\n    endpoint: http://localhost:11434\n");

        self::assertSame([], $this->loader()->load()->auditConfig);
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_it_rejects_a_config_without_a_platform(): void
    {
        $this->writeConfig("model: gpt-5.4\n");

        $this->expectException(MissingPlatformException::class);

        $this->loader()->load();
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_a_project_config_overrides_the_user_config(): void
    {
        $this->writeConfig("platform:\n  anthropic:\n    api_key: sk-user\nmodel: user-model\n");
        $projectConfigFile = $this->configHome.'/project/.symfony-security-auditor.yaml';
        $this->filesystem->dumpFile($projectConfigFile, "model: project-model\n");

        self::assertSame('project-model', $this->loader($projectConfigFile)->load()->auditConfig['model']);
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_user_config_keys_survive_when_a_project_config_omits_them(): void
    {
        $this->writeConfig("platform:\n  anthropic:\n    api_key: sk-user\nmodel: user-model\n");
        $projectConfigFile = $this->configHome.'/project/.symfony-security-auditor.yaml';
        $this->filesystem->dumpFile($projectConfigFile, "audit:\n  max_iterations: 1\n");

        self::assertSame('user-model', $this->loader($projectConfigFile)->load()->auditConfig['model']);
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_a_project_config_list_replaces_the_user_config_list_wholesale(): void
    {
        $this->writeConfig("platform:\n  anthropic:\n    api_key: sk-user\nscan:\n  included_paths: [src, config, templates]\n");
        $projectConfigFile = $this->configHome.'/project/.symfony-security-auditor.yaml';
        $this->filesystem->dumpFile($projectConfigFile, "scan:\n  included_paths: [app]\n");

        $auditConfig = $this->loader($projectConfigFile)->load()->auditConfig;

        self::assertSame(['scan' => ['included_paths' => ['app']]], $auditConfig);
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_a_project_config_overriding_one_nested_key_still_merges_sibling_keys(): void
    {
        $this->writeConfig("platform:\n  anthropic:\n    api_key: sk-user\nscan:\n  included_paths: [src]\n  excluded_paths: [vendor]\n");
        $projectConfigFile = $this->configHome.'/project/.symfony-security-auditor.yaml';
        $this->filesystem->dumpFile($projectConfigFile, "scan:\n  included_paths: [app]\n");

        $auditConfig = $this->loader($projectConfigFile)->load()->auditConfig;

        self::assertSame(['scan' => ['included_paths' => ['app'], 'excluded_paths' => ['vendor']]], $auditConfig);
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_a_missing_project_config_leaves_the_user_config_intact(): void
    {
        $this->writeConfig("platform:\n  anthropic:\n    api_key: sk-user\nmodel: user-model\n");

        self::assertSame('user-model', $this->loader($this->configHome.'/absent.yaml')->load()->auditConfig['model']);
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_it_rejects_a_missing_config_file(): void
    {
        $this->expectException(MissingPlatformException::class);

        $this->loader()->load();
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_it_rejects_an_empty_config_file(): void
    {
        $this->writeConfig('');

        $this->expectException(MissingPlatformException::class);

        $this->loader()->load();
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnresolvableConfigPathException
     * @throws MalformedProjectConfigException
     */
    public function test_it_wraps_a_malformed_yaml_config_file(): void
    {
        $this->writeConfig("platform: anthropic\n\tmodel: claude-opus-4-8");

        $this->expectException(MalformedProjectConfigException::class);

        $this->loader()->load();
    }

    private function loader(?string $projectConfigFile = null): StandaloneConfigLoader
    {
        return new StandaloneConfigLoader(
            new XdgConfigPathResolver($this->configHome, null, null),
            new StandalonePlatformConfigResolver(),
            $projectConfigFile,
        );
    }

    private function writeConfig(string $yaml): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $yaml);
    }
}
