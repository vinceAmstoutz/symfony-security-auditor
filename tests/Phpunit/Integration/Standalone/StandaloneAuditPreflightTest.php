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
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneAuditPreflight;

final class StandaloneAuditPreflightTest extends TestCase
{
    private string $configHome;

    private string $cacheHome;

    #[Override]
    protected function setUp(): void
    {
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-preflight-config-'.$suffix;
        $this->cacheHome = sys_get_temp_dir().'/ssa-preflight-cache-'.$suffix;
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove([$this->configHome, $this->cacheHome]);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_reports_no_failure_for_a_bootable_configuration(): void
    {
        $this->writeConfig("platform:\n    generic:\n        default:\n            base_url: 'http://localhost'\nmodel: 'gpt-4'\n");

        self::assertNull($this->preflight()->failureReason());
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_reports_why_a_configured_provider_without_its_bridge_cannot_boot(): void
    {
        $this->writeConfig("provider: openai\nplatform:\n    openai:\n        api_key: 'sk-test'\nmodel: 'gpt-4'\n");

        self::assertStringContainsString('symfony/ai-open-ai-platform', (string) $this->preflight()->failureReason());
    }

    public function test_it_reports_a_configuration_that_cannot_load(): void
    {
        $this->writeConfig("platform: [a, b\n");

        self::assertStringContainsString('is not valid YAML', (string) $this->preflight()->failureReason());
    }

    private function preflight(): StandaloneAuditPreflight
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, $this->cacheHome, null);

        return new StandaloneAuditPreflight(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver()),
            $xdgConfigPathResolver,
        );
    }

    private function writeConfig(string $yaml): void
    {
        (new Filesystem())->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $yaml);
    }
}
