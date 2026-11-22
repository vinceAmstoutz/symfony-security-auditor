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

use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;

/**
 * Prints the refusal of a relative `SYMFONY_SECURITY_AUDITOR_HOME`, which the
 * credential commands give before reading anything under it.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ApplicationHomeRefusal
{
    public static function reported(SymfonyStyle $symfonyStyle, ConfiguredCredentialVariable $configuredCredentialVariable): bool
    {
        $refusal = $configuredCredentialVariable->applicationHomeRefusal();
        if (null === $refusal) {
            return false;
        }

        $symfonyStyle->error($refusal);

        return true;
    }
}
