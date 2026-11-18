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

/**
 * The test request `init` offers once the configuration is written, saying
 * what it may cost before sending it, and never without someone to answer.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConnectionTestOffer
{
    private const string QUESTION = 'Send one short test request to check that the provider answers? A paid API bills it, usually well under a cent; a subscription counts it against its usage; a local model costs nothing';

    public static function make(?ConnectionTestRunnerInterface $connectionTestRunner, SymfonyStyle $symfonyStyle, bool $interactive): void
    {
        if (!$interactive || !$connectionTestRunner instanceof ConnectionTestRunnerInterface) {
            return;
        }

        if (!$symfonyStyle->confirm(self::QUESTION, false)) {
            $symfonyStyle->note('Run "doctor --check-connection" to test it later.');

            return;
        }

        $symfonyStyle->text('You answered yes: sending one test request to the provider…');

        if (!$connectionTestRunner->run($symfonyStyle)) {
            $symfonyStyle->warning('The configuration is saved. Fix the cause above, then run "doctor --check-connection" again.');
        }
    }
}
