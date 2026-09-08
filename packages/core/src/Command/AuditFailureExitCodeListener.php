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

namespace VinceAmstoutz\SecurityAuditor\Command;

use Symfony\Component\Console\Event\ConsoleErrorEvent;

/**
 * Reassigns the exit code of an `audit:run` invocation that never reached the
 * command body — a bad `project-path`, an option value the console rejects, an
 * unresolvable service — from Symfony Console's generic `1` to the dedicated
 * audit-failed code. Without this, "the auditor never ran" is indistinguishable
 * from "the auditor ran and the security gate tripped".
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AuditFailureExitCodeListener
{
    public function __invoke(ConsoleErrorEvent $consoleErrorEvent): void
    {
        if (AuditCommand::NAME !== $consoleErrorEvent->getCommand()?->getName()) {
            return;
        }

        $consoleErrorEvent->setExitCode(ExitCode::AuditFailed->value);
    }
}
