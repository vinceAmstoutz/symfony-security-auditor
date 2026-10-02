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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\OutputInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\PendingBinarySwap;

/**
 * Commits the binary swap `self-update` deferred to the end of the process.
 * By then the command has already reported the verified update and exited, so
 * a swap that fails can only be reported here — on the error output, and as
 * the exit code the entry point leaves with. A successful swap writes nothing
 * and loads no further class: the archive those classes would come from has
 * just been replaced.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PendingBinarySwapCommitter
{
    private const string NOT_APPLIED_NOTICE = 'The update was not applied: the previous version is still installed. Run "self-update" again once the cause is fixed.';

    public function __construct(
        private PendingBinarySwap $pendingBinarySwap,
    ) {}

    public function commit(OutputInterface $errorOutput): int
    {
        try {
            $this->pendingBinarySwap->commit();
        } catch (SelfUpdateFailedException $selfUpdateFailedException) {
            $errorOutput->writeln(\sprintf('<error>%s</error>', OutputFormatter::escape($selfUpdateFailedException->getMessage())));
            $errorOutput->writeln(self::NOT_APPLIED_NOTICE);

            return Command::FAILURE;
        }

        return Command::SUCCESS;
    }
}
