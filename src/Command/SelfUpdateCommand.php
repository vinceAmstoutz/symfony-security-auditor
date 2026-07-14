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
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\UnsupportedSelfUpdatePlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdaterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateStatus;

/** @internal not part of the BC promise — the command *name* (`self-update`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
final readonly class SelfUpdateCommand
{
    public const string NAME = 'self-update';

    public const string DESCRIPTION = 'Update the standalone binary to the latest released version';

    public function __construct(
        private SelfUpdaterInterface $selfUpdater,
        private string $currentVersion,
    ) {}

    /**
     * @throws SelfUpdateFailedException
     * @throws UnsupportedSelfUpdatePlatformException
     */
    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[Option(description: 'Only report whether a newer version is available; do not modify the binary.')]
        bool $check = false,
    ): int {
        return $this->report($symfonyStyle, $this->selfUpdater->run($this->currentVersion, $check));
    }

    private function report(SymfonyStyle $symfonyStyle, SelfUpdateResult $selfUpdateResult): int
    {
        match ($selfUpdateResult->status) {
            SelfUpdateStatus::AlreadyUpToDate => $symfonyStyle->success(\sprintf('Already up to date (%s).', $selfUpdateResult->currentVersion)),
            SelfUpdateStatus::UpdateAvailable => $symfonyStyle->warning(\sprintf('A newer version is available: %s (currently %s). Run "self-update" without --check to install it.', $selfUpdateResult->latestVersion, $selfUpdateResult->currentVersion)),
            SelfUpdateStatus::Updated => $symfonyStyle->success(\sprintf('Updated from %s to %s.', $selfUpdateResult->currentVersion, $selfUpdateResult->latestVersion)),
        };

        return Command::SUCCESS;
    }
}
