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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
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

    public function test_it_loads_and_normalizes_a_user_config_file(): void
    {
        $this->writeConfig("model: gpt-5.4\n");

        self::assertSame('gpt-5.4', $this->loader()->load()['model']);
    }

    public function test_it_returns_defaults_when_no_config_file_exists(): void
    {
        self::assertSame('claude-opus-4-8', $this->loader()->load()['model']);
    }

    public function test_it_treats_an_empty_config_file_as_defaults(): void
    {
        $this->writeConfig('');

        self::assertSame('claude-opus-4-8', $this->loader()->load()['model']);
    }

    private function loader(): StandaloneConfigLoader
    {
        return new StandaloneConfigLoader(
            new XdgConfigPathResolver($this->configHome, null, null),
            new AuditConfiguration(),
        );
    }

    private function writeConfig(string $yaml): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $yaml);
    }
}
