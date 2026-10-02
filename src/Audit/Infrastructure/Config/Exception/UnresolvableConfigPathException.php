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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class UnresolvableConfigPathException extends RuntimeException
{
    public static function missingHome(): self
    {
        return new self('Cannot resolve the user configuration directory: neither the relevant XDG base-directory variable nor $HOME holds an absolute path.');
    }

    public static function relativeApplicationHome(string $variable, string $value): self
    {
        return new self(\sprintf('Cannot resolve the user configuration directory: %1$s is set to "%2$s", which is not an absolute path. Resolved against the directory the command runs in, it would put the config, the credentials and the cache inside whatever project is being audited. Set %1$s to an absolute path, or unset it.', $variable, $value));
    }
}
