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

use Symfony\Component\Console\Event\ConsoleTerminateEvent;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\UpdateAvailabilityNotifierInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\SelfUpdateCommand;

/**
 * Prints an "update available" notice to stderr once a command finishes, only
 * on an interactive run and never after `self-update`. Never changes the exit
 * code.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class UpdateAvailabilityConsoleListener
{
    public function __construct(
        private UpdateAvailabilityNotifierInterface $updateAvailabilityNotifier,
        private string $currentVersion,
        private bool $disabled,
    ) {}

    public function __invoke(ConsoleTerminateEvent $consoleTerminateEvent): void
    {
        if ($this->disabled) {
            return;
        }

        if (!$consoleTerminateEvent->getInput()->isInteractive()) {
            return;
        }

        if (SelfUpdateCommand::NAME === $consoleTerminateEvent->getCommand()?->getName()) {
            return;
        }

        $notice = $this->updateAvailabilityNotifier->availableUpdateNotice($this->currentVersion);
        if (null === $notice) {
            return;
        }

        $this->errorOutput($consoleTerminateEvent->getOutput())->writeln(\sprintf('<comment>%s</comment>', $notice));
    }

    private function errorOutput(OutputInterface $output): OutputInterface
    {
        return $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
    }
}
