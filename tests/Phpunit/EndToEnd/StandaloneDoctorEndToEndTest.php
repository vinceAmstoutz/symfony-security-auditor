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

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplicationFactory;

final class StandaloneDoctorEndToEndTest extends TestCase
{
    private Filesystem $filesystem;

    private string $configHome;

    private string $cacheHome;

    private string $dataHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-doctor-e2e-config-'.$suffix;
        $this->cacheHome = sys_get_temp_dir().'/ssa-doctor-e2e-cache-'.$suffix;
        $this->dataHome = sys_get_temp_dir().'/ssa-doctor-e2e-data-'.$suffix;
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove([$this->configHome, $this->cacheHome, $this->dataHome]);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_standalone_doctor_reports_a_ready_environment_end_to_end(): void
    {
        $this->filesystem->dumpFile(
            $this->configHome.'/symfony-security-auditor/config.yaml',
            "platform:\n    generic:\n        default:\n            base_url: 'http://localhost'\nmodel: 'gpt-4'\n",
        );
        $this->filesystem->dumpFile($this->dataHome.'/symfony-security-auditor/vendor/autoload.php', "<?php\n");

        $commandTester = $this->doctorCommandTester();

        $exitCode = $commandTester->execute([]);

        self::assertSame(Command::SUCCESS, $exitCode);
        $display = $commandTester->getDisplay();
        self::assertStringContainsString('[OK] Configuration:', $display);
        self::assertStringContainsString('[OK] Provider bridge:', $display);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_standalone_doctor_fails_end_to_end_when_the_installed_bridge_does_not_match_the_provider(): void
    {
        $this->filesystem->dumpFile(
            $this->configHome.'/symfony-security-auditor/config.yaml',
            "provider: openai\nplatform:\n    openai:\n        api_key: 'sk-e2e'\nmodel: 'gpt-4'\n",
        );
        $this->filesystem->dumpFile($this->dataHome.'/symfony-security-auditor/vendor/autoload.php', "<?php\n");

        $commandTester = $this->doctorCommandTester();

        $exitCode = $commandTester->execute([]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('Installed, but the audit cannot start with it', $commandTester->getDisplay());
    }

    public function test_the_standalone_doctor_fails_end_to_end_when_the_environment_is_not_configured(): void
    {
        $commandTester = $this->doctorCommandTester();

        $exitCode = $commandTester->execute([]);

        self::assertSame(Command::FAILURE, $exitCode);
        $display = $commandTester->getDisplay();
        self::assertStringContainsString('No provider is configured', $display);
        self::assertStringContainsString('Not installed', $display);
    }

    private function doctorCommandTester(): CommandTester
    {
        $application = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => $this->configHome,
            'XDG_CACHE_HOME' => $this->cacheHome,
            'XDG_DATA_HOME' => $this->dataHome,
        ])->create();

        return new CommandTester($application->find(DoctorCommand::NAME));
    }
}
