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
        (new Filesystem())->dumpFile(
            $this->dataHome.'/symfony-security-auditor/vendor/autoload.php',
            \sprintf("<?php\n\nthrow new RuntimeException('%s');\n", self::PLATFORM_CHECK_FAILURE),
        );
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->dataHome);
    }

    #[MaximumDuration(4000)]
    public function test_a_bridge_tree_the_binary_cannot_load_is_reported_and_the_command_still_runs(): void
    {
        $process = new Process(
            [\PHP_BINARY, \dirname(__DIR__, 4).'/bin/symfony-security-auditor', '--version'],
            null,
            [
                'XDG_DATA_HOME' => $this->dataHome,
                'XDG_CONFIG_HOME' => $this->dataHome.'/config',
                'XDG_CACHE_HOME' => $this->dataHome.'/cache',
                'SSA_NO_UPDATE_CHECK' => '1',
                'SYMFONY_SECURITY_AUDITOR_HOME' => false,
            ],
        );
        $process->run();

        self::assertSame(0, $process->getExitCode(), $process->getErrorOutput());
        self::assertStringContainsString(
            \sprintf('The provider bridge under "%s/symfony-security-auditor" cannot be loaded by this binary: %s', $this->dataHome, self::PLATFORM_CHECK_FAILURE),
            $process->getErrorOutput(),
        );
        self::assertStringContainsString('Run "init --provider=<platform>" again to rebuild it for the bundled PHP.', $process->getErrorOutput());
        self::assertStringContainsString('symfony-security-auditor', $process->getOutput());
    }
}
