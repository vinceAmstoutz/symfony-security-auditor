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
 * once to download the provider bridge: whether it is Composer or the PHP it
 * runs on that is missing, what the system reported, and how to install both
 * on the operating system the binary was built for.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ComposerSetupAdvice
{
    private const string DOWNLOAD_PAGE = 'https://getcomposer.org/download/';

    private const string PHP_NOT_FOUND = '/\bphp(?:\.exe)?[\'"\x{2018}\x{2019}]?:? (?:is )?(?:not found|command not found|not recognized)|\bphp[\'"\x{2018}\x{2019}]?: No such file|command not found: php\b/iu';

    public function __construct(
        private string $osFamily = \PHP_OS_FAMILY,
    ) {}

    public function problem(ComposerProbe $composerProbe): string
    {
        return implode("\n", [
            1 === preg_match(self::PHP_NOT_FOUND, $composerProbe->failure)
                ? 'init cannot continue: Composer is installed, but PHP, which it runs on, is not.'
                : 'init cannot continue: Composer, which it uses to download the package for your AI provider, is not installed or does not start.',
            \sprintf('  It reported: %s', OutputFormatter::escape($composerProbe->failure)),
            'Only this one-time download needs PHP and Composer, not auditing. Install them, then run "init" again.',
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
