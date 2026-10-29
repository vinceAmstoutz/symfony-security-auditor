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
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

/**
 * Runs the real `bin/symfony-security-auditor` entry script in the hidden
 * Composer mode the bridge installer starts it in, with a stand-in for
 * `composer.phar` that prints what it was started with.
 */
final class StandaloneComposerModeEndToEndTest extends TestCase
{
    private Filesystem $filesystem;

    private string $base;

    private string $composerPhar;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->base = sys_get_temp_dir().'/ssa-composer-mode-'.bin2hex(random_bytes(4));
        $this->composerPhar = $this->base.'/composer.phar';

        $this->filesystem->dumpFile($this->composerPhar, '<?php echo json_encode($_SERVER[\'argv\']);');
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->base);
    }

    public function test_it_runs_the_composer_phar_with_the_command_line_it_was_given(): void
    {
        $process = $this->runInComposerMode(['require', 'symfony/ai-anthropic-platform', '--no-interaction']);

        self::assertSame(
            json_encode([$this->composerPhar, 'require', 'symfony/ai-anthropic-platform', '--no-interaction']),
            $process->getOutput(),
        );
    }

    public function test_the_processes_composer_starts_run_this_binary_in_its_usual_mode(): void
    {
        $this->filesystem->dumpFile($this->composerPhar, '<?php var_export([getenv(\'SYMFONY_SECURITY_AUDITOR_COMPOSER_PHAR\'), $_SERVER[\'SYMFONY_SECURITY_AUDITOR_COMPOSER_PHAR\'] ?? false, $_ENV[\'SYMFONY_SECURITY_AUDITOR_COMPOSER_PHAR\'] ?? false]);');

        self::assertSame(var_export([false, false, false], true), $this->runInComposerMode([])->getOutput());
    }

    #[MaximumDuration(4000)]
    public function test_init_installs_the_bridge_with_its_own_composer_rather_than_one_on_the_host(): void
    {
        $process = new Process(
            [\PHP_BINARY, \dirname(__DIR__, 3).'/bin/symfony-security-auditor', 'init', '--no-interaction', '--no-ansi', '--provider=anthropic', '--model=claude-opus-5-5', '--env-var=ANTHROPIC_API_KEY'],
            $this->base,
            [
                'HOME' => $this->base,
                'PATH' => $this->base.'/empty-path',
                'XDG_CONFIG_HOME' => $this->base.'/config',
                'XDG_DATA_HOME' => $this->base.'/data',
                'SSA_NO_UPDATE_CHECK' => '1',
            ],
        );
        $process->run();

        self::assertStringContainsString('Could not download composer.phar 2.8.12', preg_replace('/\s+/', ' ', $process->getOutput().$process->getErrorOutput()) ?? '');
    }

    /**
     * @param list<string> $arguments
     */
    private function runInComposerMode(array $arguments): Process
    {
        $process = new Process(
            [\PHP_BINARY, \dirname(__DIR__, 3).'/bin/symfony-security-auditor', ...$arguments],
            $this->base,
            [
                'HOME' => $this->base,
                'XDG_CONFIG_HOME' => $this->base.'/config',
                'XDG_DATA_HOME' => $this->base.'/data',
                'SYMFONY_SECURITY_AUDITOR_COMPOSER_PHAR' => $this->composerPhar,
            ],
        );
        $process->run();

        return $process;
    }
}
