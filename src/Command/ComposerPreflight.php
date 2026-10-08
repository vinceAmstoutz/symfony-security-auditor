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

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Stops `init` before its first question when `composer` cannot run, since
 * every path of `init` ends in a `composer require`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ComposerPreflight
{
    public function __construct(
        private ComposerAvailabilityCheckerInterface $composerAvailabilityChecker,
        private ComposerSetupAdvice $composerSetupAdvice = new ComposerSetupAdvice(),
    ) {}

    /**
     * @return ?int the exit code `init` stops with, or null when `composer` runs
     */
    public function refusal(SymfonyStyle $symfonyStyle): ?int
    {
        $composerProbe = $this->composerAvailabilityChecker->probe();

        if ($composerProbe->isAvailable) {
            return null;
        }

        $symfonyStyle->error($this->composerSetupAdvice->problem($composerProbe));
        $symfonyStyle->writeln($this->composerSetupAdvice->installInstructions());

        return Command::FAILURE;
    }
}
