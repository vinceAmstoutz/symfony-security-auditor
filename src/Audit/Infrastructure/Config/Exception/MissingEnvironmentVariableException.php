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
final class MissingEnvironmentVariableException extends RuntimeException
{
    /**
     * @param bool $concernsCredential whether the unset variable holds the API key rather than another setting
     */
    public function __construct(string $message, public readonly bool $concernsCredential)
    {
        parent::__construct($message);
    }

    public static function forName(string $name): self
    {
        return new self(\sprintf(
            'No API key available. Your config reads it from "%1$s", which is not set in the environment and has nothing stored for it. Fix it in whichever way suits you: run "auth:set --env-var=%1$s" to store the key on this machine (kept in an owner-only file, so no shell export is needed again); or export %1$s in your shell; or pass it per run from a password manager, e.g. %1$s=$(pass show anthropic/api-key) symfony-security-auditor audit . — run "auth:status --env-var=%1$s" to see what is currently resolved.',
            $name,
        ), true);
    }

    public static function forSetting(string $name): self
    {
        return new self(\sprintf('The environment variable "%s", referenced by your config, is not set.', $name), false);
    }
}
