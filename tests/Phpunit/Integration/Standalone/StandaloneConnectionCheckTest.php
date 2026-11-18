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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Standalone;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneConnectionCheck;

final class StandaloneConnectionCheckTest extends TestCase
{
    private string $configHome;

    private string $cacheHome;

    #[Override]
    protected function setUp(): void
    {
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-connection-config-'.$suffix;
        $this->cacheHome = sys_get_temp_dir().'/ssa-connection-cache-'.$suffix;
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove([$this->configHome, $this->cacheHome]);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_reports_no_failure_once_the_configured_provider_answers(): void
    {
        (new Filesystem())->dumpFile(
            $this->configHome.'/symfony-security-auditor/config.yaml',
            "platform:\n    generic:\n        default:\n            base_url: 'http://localhost'\nmodel: 'gpt-4'\n",
        );

        self::assertNull($this->connectionCheck()->failureReason());
    }

    public function test_it_reports_a_configuration_that_cannot_load(): void
    {
        (new Filesystem())->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', "platform: [a, b\n");

        self::assertStringContainsString('is not valid YAML', (string) $this->connectionCheck()->failureReason());
    }

    private function connectionCheck(): StandaloneConnectionCheck
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, $this->cacheHome, null);

        return new StandaloneConnectionCheck(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver()),
            $xdgConfigPathResolver,
        );
    }
}
