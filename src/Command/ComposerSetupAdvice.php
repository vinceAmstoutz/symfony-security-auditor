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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * What `init` tells a user whose machine cannot run `composer`, which it needs
 * once to download the provider bridge: why the probe failed and how to
 * install Composer — with the PHP it runs on — on the operating system the
 * binary was built for.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ComposerSetupAdvice
{
    private const string DOWNLOAD_PAGE = 'https://getcomposer.org/download/';

    public function __construct(
        private string $osFamily = \PHP_OS_FAMILY,
    ) {}

    public function problem(ComposerProbe $composerProbe): string
    {
        return implode("\n", [
            'init downloads the provider bridge with Composer, which needs PHP, and running "composer --version" failed:',
            \sprintf('  %s', OutputFormatter::escape($composerProbe->failure)),
            'Only this one-time download needs them, not auditing. Install both, then run "init" again.',
        ]);
    }

    public function installInstructions(): string
    {
        return match ($this->osFamily) {
            'Linux' => implode("\n", [
                '  Debian/Ubuntu, WSL included: sudo apt update && sudo apt install -y php-cli php-curl php-mbstring php-xml unzip composer',
                '  Other distributions: the php-cli, composer and unzip packages of your package manager',
            ]),
            'Darwin' => implode("\n", [
                '  brew install composer (Homebrew installs PHP with it)',
                \sprintf('  Without Homebrew: %s', self::DOWNLOAD_PAGE),
            ]),
            'Windows' => implode("\n", [
                '  PHP: https://windows.php.net/download/',
                \sprintf('  Composer: the Windows installer at %s', self::DOWNLOAD_PAGE),
                '  Then open a new terminal, so that it finds both.',
            ]),
            default => \sprintf('  Composer: %s — PHP: https://www.php.net/downloads', self::DOWNLOAD_PAGE),
        };
    }
}
