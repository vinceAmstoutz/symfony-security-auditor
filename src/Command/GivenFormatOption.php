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

use Symfony\Component\Console\Input\ArgvInput;
use Symfony\Component\Console\Input\InputInterface;

/**
 * Whether the command line names `--format` or `-f`, which the console cannot
 * tell from the option's own default once the input is bound. A short option
 * can sit inside a cluster of flags (`-nf json`); the only flags the command
 * accepts are the console's global ones, so the cluster is read up to `f`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class GivenFormatOption
{
    private const string CLUSTERED_SHORTCUT = '/^-[hnqvV]*f/';

    public static function in(InputInterface $input): bool
    {
        return $input->hasParameterOption(['--format', '-f'], true)
            || ($input instanceof ArgvInput && self::clusters($input));
    }

    private static function clusters(ArgvInput $argvInput): bool
    {
        foreach ($argvInput->getRawTokens() as $token) {
            if ('--' === $token) {
                return false;
            }

            if (1 === preg_match(self::CLUSTERED_SHORTCUT, $token)) {
                return true;
            }
        }

        return false;
    }
}
