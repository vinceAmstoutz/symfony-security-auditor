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
    public function test_it_says_what_failed_and_that_only_the_one_time_download_needs_it(): void
    {
        $problem = (new ComposerSetupAdvice('Linux'))->problem(ComposerProbe::unavailable('php: not found'));

        self::assertSame(
            implode("\n", [
                'init downloads the provider bridge with Composer, which needs PHP, and running "composer --version" failed:',
                '  php: not found',
                'Only this one-time download needs them, not auditing. Install both, then run "init" again.',
            ]),
            $problem,
        );
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

        self::assertStringContainsString('  <error>boom</error>', (new OutputFormatter())->format($problem));
    }

    public function test_it_defaults_to_the_operating_system_it_runs_on(): void
    {
        self::assertSame((new ComposerSetupAdvice(\PHP_OS_FAMILY))->installInstructions(), (new ComposerSetupAdvice())->installInstructions());
    }
}
