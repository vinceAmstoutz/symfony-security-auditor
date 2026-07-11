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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

final class XdgConfigPathResolverTest extends TestCase
{
    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_resolves_the_config_file_under_xdg_config_home_when_set(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver('/xdg/config', null, '/home/dev');

        self::assertSame('/xdg/config/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_falls_back_to_home_dot_config_when_xdg_config_home_is_empty(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver('', null, '/home/dev');

        self::assertSame('/home/dev/.config/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_falls_back_to_home_dot_config_when_xdg_config_home_is_relative(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver('.config', null, '/home/dev');

        self::assertSame('/home/dev/.config/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_treats_a_windows_drive_letter_mid_path_as_relative_not_absolute(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver('rel/C:/x', null, '/home/dev');

        self::assertSame('/home/dev/.config/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_resolves_the_cache_dir_under_xdg_cache_home_when_set(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, '/xdg/cache', '/home/dev');

        self::assertSame('/xdg/cache/symfony-security-auditor', $xdgConfigPathResolver->cacheDir());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_falls_back_to_home_dot_cache_when_xdg_cache_home_is_unset(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, null, '/home/dev');

        self::assertSame('/home/dev/.cache/symfony-security-auditor', $xdgConfigPathResolver->cacheDir());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_resolves_the_data_dir_under_xdg_data_home_when_set(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, null, '/home/dev', '/xdg/data');

        self::assertSame('/xdg/data/symfony-security-auditor', $xdgConfigPathResolver->dataDir());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_falls_back_to_home_dot_local_share_when_xdg_data_home_is_unset(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, null, '/home/dev');

        self::assertSame('/home/dev/.local/share/symfony-security-auditor', $xdgConfigPathResolver->dataDir());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_rejects_resolving_a_config_file_without_any_home(): void
    {
        $this->expectException(UnresolvableConfigPathException::class);

        (new XdgConfigPathResolver(null, null, null))->configFile();
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_maps_windows_environment_to_the_native_app_data_directories(): void
    {
        $xdgConfigPathResolver = XdgConfigPathResolver::fromEnvironment([
            'APPDATA' => 'C:/Users/dev/AppData/Roaming',
            'LOCALAPPDATA' => 'C:/Users/dev/AppData/Local',
            'USERPROFILE' => 'C:/Users/dev',
        ], 'Windows');

        self::assertSame('C:/Users/dev/AppData/Roaming/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
        self::assertSame('C:/Users/dev/AppData/Local/symfony-security-auditor', $xdgConfigPathResolver->cacheDir());
        self::assertSame('C:/Users/dev/AppData/Local/symfony-security-auditor', $xdgConfigPathResolver->dataDir());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_falls_back_to_the_windows_user_profile_when_no_app_data_is_set(): void
    {
        $xdgConfigPathResolver = XdgConfigPathResolver::fromEnvironment([
            'USERPROFILE' => 'C:/Users/dev',
        ], 'Windows');

        self::assertSame('C:/Users/dev/.config/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_ignores_the_windows_user_profile_on_a_unix_system(): void
    {
        $this->expectException(UnresolvableConfigPathException::class);

        XdgConfigPathResolver::fromEnvironment(['USERPROFILE' => 'C:/Users/dev'], 'Linux')->configFile();
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_prefers_xdg_variables_over_the_windows_directories(): void
    {
        $xdgConfigPathResolver = XdgConfigPathResolver::fromEnvironment([
            'XDG_CONFIG_HOME' => '/xdg/config',
            'XDG_CACHE_HOME' => '/xdg/cache',
            'XDG_DATA_HOME' => '/xdg/data',
            'APPDATA' => 'C:/Users/dev/AppData/Roaming',
            'LOCALAPPDATA' => 'C:/Users/dev/AppData/Local',
        ], 'Windows');

        self::assertSame('/xdg/config/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
        self::assertSame('/xdg/cache/symfony-security-auditor', $xdgConfigPathResolver->cacheDir());
        self::assertSame('/xdg/data/symfony-security-auditor', $xdgConfigPathResolver->dataDir());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_maps_a_unix_environment_to_the_home_directory(): void
    {
        $xdgConfigPathResolver = XdgConfigPathResolver::fromEnvironment([
            'HOME' => '/home/dev',
            'APPDATA' => 'C:/Users/dev/AppData/Roaming',
        ], 'Linux');

        self::assertSame('/home/dev/.config/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
        self::assertSame('/home/dev/.cache/symfony-security-auditor', $xdgConfigPathResolver->cacheDir());
        self::assertSame('/home/dev/.local/share/symfony-security-auditor', $xdgConfigPathResolver->dataDir());
    }

    /**
     * @throws UnresolvableConfigPathException
     */
    public function test_it_prefers_xdg_variables_over_the_unix_home_directory(): void
    {
        $xdgConfigPathResolver = XdgConfigPathResolver::fromEnvironment([
            'XDG_CONFIG_HOME' => '/xdg/config',
            'HOME' => '/home/dev',
        ], 'Linux');

        self::assertSame('/xdg/config/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
    }
}
