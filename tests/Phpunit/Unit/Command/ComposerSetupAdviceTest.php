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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Formatter\OutputFormatter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ComposerProbe;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ComposerSetupAdvice;

final class ComposerSetupAdviceTest extends TestCase
{
    #[DataProvider('failuresNamingPhp')]
    public function test_it_names_the_missing_php_when_composer_cannot_find_it(string $failure): void
    {
        $problem = (new ComposerSetupAdvice('Linux'))->problem(ComposerProbe::unavailable($failure));

        self::assertSame(
            implode("\n", [
                'init cannot continue: Composer is installed, but PHP, which it runs on, is not.',
                \sprintf('  It reported: %s', $failure),
                'Only this one-time download needs PHP and Composer, not auditing. Install them, then run "init" again.',
            ]),
            $problem,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function failuresNamingPhp(): iterable
    {
        yield 'dash, behind a Windows shim in WSL' => ['/mnt/c/ProgramData/ComposerSetup/bin/composer: 14: php: not found'];
        yield 'bash' => ['composer: line 3: php: command not found'];
        yield 'zsh' => ['zsh: command not found: php'];
        yield 'a shebang resolving php, straight quotes' => ["/usr/bin/env: 'php': No such file or directory"];
        yield 'a shebang resolving php, curly quotes' => ["/usr/bin/env: \u{2018}php\u{2019}: No such file or directory"];
        yield 'the Windows command prompt' => ["'php' is not recognized as an internal or external command,"];
        yield 'the Windows command prompt, naming the executable' => ['php.exe is not recognized as an internal or external command,'];
    }

    #[DataProvider('failuresNotNamingPhp')]
    public function test_it_says_composer_is_missing_when_php_is_not_what_failed(string $failure): void
    {
        $problem = (new ComposerSetupAdvice('Linux'))->problem(ComposerProbe::unavailable($failure));

        self::assertSame(
            implode("\n", [
                'init cannot continue: Composer, which it uses to download the package for your AI provider, is not installed or does not start.',
                \sprintf('  It reported: %s', $failure),
                'Only this one-time download needs PHP and Composer, not auditing. Install them, then run "init" again.',
            ]),
            $problem,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function failuresNotNamingPhp(): iterable
    {
        yield 'Composer absent from the PATH' => ['sh: 1: exec: composer: not found'];
        yield 'Composer absent on the Windows command prompt' => ["'composer' is not recognized as an internal or external command,"];
        yield 'a path that merely contains php' => ['/opt/php/bin/composer: not found'];
        yield 'no output at all' => ['"composer --version" exited with code 3'];
    }

    #[DataProvider('operatingSystems')]
    public function test_it_gives_the_install_instructions_of_the_operating_system(string $osFamily, string $expectedInstructions): void
    {
        self::assertSame($expectedInstructions, (new ComposerSetupAdvice($osFamily))->installInstructions());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function operatingSystems(): iterable
    {
        yield 'Linux' => ['Linux', implode("\n", [
            '  Debian/Ubuntu, WSL included: sudo apt update && sudo apt install -y php-cli php-curl php-mbstring php-xml unzip composer',
            '  Other distributions: the php-cli, composer and unzip packages of your package manager',
        ])];
        yield 'macOS' => ['Darwin', implode("\n", [
            '  brew install composer (Homebrew installs PHP with it)',
            '  Without Homebrew: https://getcomposer.org/download/',
        ])];
        yield 'Windows' => ['Windows', implode("\n", [
            '  PHP: https://windows.php.net/download/',
            '  Composer: the Windows installer at https://getcomposer.org/download/',
            '  Then open a new terminal, so that it finds both.',
        ])];
        yield 'any other system' => ['BSD', '  Composer: https://getcomposer.org/download/ — PHP: https://www.php.net/downloads'];
    }

    public function test_it_escapes_what_the_probe_reported_so_that_the_console_prints_it_as_written(): void
    {
        $problem = (new ComposerSetupAdvice('Linux'))->problem(ComposerProbe::unavailable('<error>boom</error>'));

        self::assertStringContainsString('  It reported: <error>boom</error>', (new OutputFormatter())->format($problem));
    }

    public function test_it_defaults_to_the_operating_system_it_runs_on(): void
    {
        self::assertSame((new ComposerSetupAdvice(\PHP_OS_FAMILY))->installInstructions(), (new ComposerSetupAdvice())->installInstructions());
    }
}
