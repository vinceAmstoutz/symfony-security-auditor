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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

final class StandaloneEntryPointTest extends TestCase
{
    private const string PLATFORM_CHECK_FAILURE = 'Composer detected issues in your platform.';

    private string $dataHome;

    #[Override]
    protected function setUp(): void
    {
        $this->dataHome = sys_get_temp_dir().'/ssa-entry-point-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->dataHome);
    }

    #[DataProvider('platformChecksRefusingThisPhp')]
    #[MaximumDuration(4000)]
    public function test_a_bridge_tree_the_binary_cannot_load_is_reported_and_the_command_still_runs(string $platformCheck): void
    {
        (new Filesystem())->dumpFile($this->dataHome.'/symfony-security-auditor/vendor/autoload.php', \sprintf("<?php\n\n%s\n", $platformCheck));

        $process = $this->versionProcess();
        $process->run();

        self::assertSame(0, $process->getExitCode(), $process->getErrorOutput());
        self::assertStringContainsString(
            \sprintf('The provider bridge under "%s/symfony-security-auditor" cannot be loaded by this binary: %s', $this->dataHome, self::PLATFORM_CHECK_FAILURE),
            $process->getErrorOutput(),
        );
        self::assertStringContainsString('Run "init --provider=<platform> --force" to rebuild it for the bundled PHP.', $process->getErrorOutput());
        self::assertStringContainsString('symfony-security-auditor', $process->getOutput());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function platformChecksRefusingThisPhp(): iterable
    {
        yield 'thrown, as Composer 2.8.10 and later generate it' => [\sprintf('throw new RuntimeException(%s);', var_export(self::PLATFORM_CHECK_FAILURE, true))];
        yield 'raised as a fatal error, as earlier Composer versions generate it' => [\sprintf('trigger_error(%s, E_USER_ERROR);', var_export(self::PLATFORM_CHECK_FAILURE, true))];
    }

    #[MaximumDuration(4000)]
    public function test_the_deprecation_of_the_older_platform_check_does_not_reach_the_terminal(): void
    {
        (new Filesystem())->dumpFile(
            $this->dataHome.'/symfony-security-auditor/vendor/autoload.php',
            \sprintf("<?php\n\ntrigger_error(%s, E_USER_ERROR);\n", var_export(self::PLATFORM_CHECK_FAILURE, true)),
        );

        $process = $this->versionProcess();
        $process->run();

        self::assertStringNotContainsString('Deprecated', $process->getOutput().$process->getErrorOutput());
    }

    private function versionProcess(): Process
    {
        return new Process(
            [\PHP_BINARY, '-d', 'display_errors=stderr', '-d', 'error_reporting=-1', \dirname(__DIR__, 4).'/bin/symfony-security-auditor', '--version'],
            null,
            [
                'XDG_DATA_HOME' => $this->dataHome,
                'XDG_CONFIG_HOME' => $this->dataHome.'/config',
                'XDG_CACHE_HOME' => $this->dataHome.'/cache',
                'SSA_NO_UPDATE_CHECK' => '1',
                'SYMFONY_SECURITY_AUDITOR_HOME' => false,
            ],
        );
    }
}
