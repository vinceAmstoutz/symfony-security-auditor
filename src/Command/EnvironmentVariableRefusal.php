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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EnvironmentVariableName;

/**
 * The credential commands give `init`'s answer to a variable name no `%env()%`
 * placeholder could ever read back: say why, and exit `2` instead of acting.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class EnvironmentVariableRefusal
{
    public static function reported(SymfonyStyle $symfonyStyle, string $variableName): bool
    {
        $violation = EnvironmentVariableName::violationFor($variableName);
        if (null === $violation) {
            return false;
        }

        $symfonyStyle->error($violation);

        return true;
    }
}
