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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;

/**
 * The variable's value is named only by the masked preview a key gets, never
 * in full: a user who put `file:` in front of the variable that holds the key
 * itself would otherwise read their key back in an error message.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class UnreadableCredentialFileException extends RuntimeException
{
    public static function forVariable(string $variableName, string $path): self
    {
        return new self(\sprintf(
            'The credential file your config reads through "%1$s" could not be read (%1$s holds "%2$s"). Check that it names a readable file.',
            $variableName,
            CredentialIdentity::of($path)->maskedPreview,
        ));
    }

    public static function forBlankFile(string $variableName, string $path): self
    {
        return new self(\sprintf(
            'The credential file your config reads through "%1$s" is empty (%1$s holds "%2$s").',
            $variableName,
            CredentialIdentity::of($path)->maskedPreview,
        ));
    }
}
