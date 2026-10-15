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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner;

/**
 * The environment a scenario runs in, the same wherever it runs: a CI runner
 * exports `GITHUB_ACTIONS`, which changes how reports are written, and its
 * `LANG`, which decides whether the banner is drawn in UTF-8; a developer's
 * shell exports a terminal width, which changes how the console wraps text.
 */
final readonly class ProcessEnvironment
{
    private const string SCRIPT_NAME = 'symfony-security-auditor';

    private const array HOST_VARIABLES = ['GITHUB_ACTIONS', 'CI', 'SSA_NO_UPDATE_CHECK', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'SYMFONY_SECURITY_AUDITOR_HOME', 'APPDATA', 'LOCALAPPDATA', 'NO_COLOR', 'TERM', 'COLUMNS', 'LINES', 'SHELL_VERBOSITY', 'LANG', 'LANGUAGE', 'LC_ALL', 'LC_CTYPE', 'LC_MESSAGES', 'LC_NUMERIC', 'LC_COLLATE', 'LC_TIME'];

    /**
     * @param array<string, string> $variables
     */
    public static function apply(Workspace $workspace, array $variables): void
    {
        foreach (self::HOST_VARIABLES as $hostVariable) {
            self::unset($hostVariable);
        }

        $path = getenv('PATH');
        $fixed = [
            'LC_ALL' => 'C',
            'COLUMNS' => '120',
            'LINES' => '50',
            'TERM' => 'dumb',
            'NO_COLOR' => '1',
            'SSA_NO_UPDATE_CHECK' => '1',
            'HOME' => $workspace->resolve('home'),
            'PATH' => \sprintf('%s:%s', $workspace->resolve('bin'), \is_string($path) ? $path : '/usr/bin:/bin'),
        ];

        foreach ([...$fixed, ...$variables] as $name => $value) {
            self::set($name, $workspace->expand($value));
        }

        $_SERVER['PHP_SELF'] = self::SCRIPT_NAME;
        $_SERVER['SCRIPT_NAME'] = self::SCRIPT_NAME;
    }

    public static function set(string $name, string $value): void
    {
        putenv(\sprintf('%s=%s', $name, $value));
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }

    public static function unset(string $name): void
    {
        putenv($name);
        unset($_ENV[$name], $_SERVER[$name]);
    }

    /**
     * @return array<string, string>
     */
    public static function current(): array
    {
        return getenv();
    }
}
