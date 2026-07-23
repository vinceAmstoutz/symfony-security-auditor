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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\ApplicationTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\UpdateAvailabilityNotifierInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplicationFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\UpdateAvailabilityConsoleListener;

final class StandaloneUpdateNoticeEndToEndTest extends TestCase
{
    private const string NOTICE = 'A new version (2.0.0) is available.';

    private Filesystem $filesystem;

    private string $configHome;

    private string $cacheHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-update-e2e-config-'.$suffix;
        $this->cacheHome = sys_get_temp_dir().'/ssa-update-e2e-cache-'.$suffix;
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove([$this->configHome, $this->cacheHome]);
    }

    public function test_it_prints_the_update_notice_to_stderr_after_a_command_on_an_interactive_run(): void
    {
        $applicationTester = $this->runListCommand(self::NOTICE, false, true);

        self::assertStringContainsString(self::NOTICE, $applicationTester->getErrorOutput());
    }

    public function test_it_keeps_stdout_free_of_the_update_notice(): void
    {
        $applicationTester = $this->runListCommand(self::NOTICE, false, true);

        self::assertStringNotContainsString(self::NOTICE, $applicationTester->getDisplay());
    }

    public function test_it_stays_silent_on_a_non_interactive_run(): void
    {
        $applicationTester = $this->runListCommand(self::NOTICE, false, false);

        self::assertStringNotContainsString(self::NOTICE, $applicationTester->getErrorOutput());
    }

    public function test_it_stays_silent_when_update_checks_are_disabled(): void
    {
        $applicationTester = $this->runListCommand(self::NOTICE, true, true);

        self::assertStringNotContainsString(self::NOTICE, $applicationTester->getErrorOutput());
    }

    private function runListCommand(string $notice, bool $disabled, bool $interactive): ApplicationTester
    {
        $updateAvailabilityNotifier = self::createStub(UpdateAvailabilityNotifierInterface::class);
        $updateAvailabilityNotifier->method('availableUpdateNotice')->willReturn($notice);

        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, $this->cacheHome, null);
        $application = (new StandaloneApplicationFactory(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver()),
            $xdgConfigPathResolver,
            self::createStub(BridgeInstallerInterface::class),
            updateAvailabilityConsoleListener: new UpdateAvailabilityConsoleListener($updateAvailabilityNotifier, '1.0.0', $disabled),
        ))->create();
        $application->setAutoExit(false);

        $applicationTester = new ApplicationTester($application);
        $applicationTester->run(['command' => 'list'], ['interactive' => $interactive, 'capture_stderr_separately' => true]);

        return $applicationTester;
    }
}
