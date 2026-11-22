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

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/** @internal not part of the BC promise — the command *name* (`auth:test`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
final readonly class AuthTestCommand
{
    public const string NAME = 'auth:test';

    public const string DESCRIPTION = 'Send one short request to check that the provider answers (a paid API bills it, usually well under a cent)';

    public function __construct(
        private ConnectionCheckInterface $connectionCheck,
    ) {}

    public function __invoke(SymfonyStyle $symfonyStyle): int
    {
        $failureReason = $this->connectionCheck->failureReason();
        if (null !== $failureReason) {
            $symfonyStyle->error(\sprintf(ConnectionProbe::FAILURE, $failureReason));

            return Command::FAILURE;
        }

        $symfonyStyle->success('The provider answered the test request. You can run an audit now.');

        return Command::SUCCESS;
    }
}
