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
    public function test_it_resolves_the_config_file_under_xdg_config_home_when_set(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver('/xdg/config', null, '/home/dev');

        self::assertSame('/xdg/config/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
    }

    public function test_it_falls_back_to_home_dot_config_when_xdg_config_home_is_empty(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver('', null, '/home/dev');

        self::assertSame('/home/dev/.config/symfony-security-auditor/config.yaml', $xdgConfigPathResolver->configFile());
    }

    public function test_it_resolves_the_cache_dir_under_xdg_cache_home_when_set(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, '/xdg/cache', '/home/dev');

        self::assertSame('/xdg/cache/symfony-security-auditor', $xdgConfigPathResolver->cacheDir());
    }

    public function test_it_falls_back_to_home_dot_cache_when_xdg_cache_home_is_unset(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, null, '/home/dev');

        self::assertSame('/home/dev/.cache/symfony-security-auditor', $xdgConfigPathResolver->cacheDir());
    }

    public function test_it_resolves_the_data_dir_under_xdg_data_home_when_set(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, null, '/home/dev', '/xdg/data');

        self::assertSame('/xdg/data/symfony-security-auditor', $xdgConfigPathResolver->dataDir());
    }

    public function test_it_falls_back_to_home_dot_local_share_when_xdg_data_home_is_unset(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, null, '/home/dev');

        self::assertSame('/home/dev/.local/share/symfony-security-auditor', $xdgConfigPathResolver->dataDir());
    }

    public function test_it_rejects_resolving_a_config_file_without_any_home(): void
    {
        $this->expectException(UnresolvableConfigPathException::class);

        (new XdgConfigPathResolver(null, null, null))->configFile();
    }
}
