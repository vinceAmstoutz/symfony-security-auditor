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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class SchedulerAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::SCHEDULER;
    }

    #[Override]
    public function priority(): int
    {
        return 100;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="scheduler">
            Hunt:
            - `#[AsSchedule]` / `ScheduleProviderInterface::getSchedule()` registering tasks that read user-input from DB and pass it unsanitized to `Process` / shell.
            - Cron-like schedules invoking privileged operations (mass email, payout, account deletion) without an audit log or kill-switch.
            - Tasks with no lock (`LockableTrait`, `LockFactory`) — overlapping runs cause duplicate billing or double notifications.
            - Schedules running with `RunCommandMessage` whose `command` string is built from user input — RCE via the schedule.
            - Recurring tasks fetching remote URLs (`HttpClient::request($urlFromDb)`) without a host allowlist (SSRF).
            Do NOT flag:
            - `RecurringMessage::every('1 hour', $message)` with a statically-typed message class and no user input.
            - Schedules using `LockableTrait` with a project-unique lock name.
            </skills>
            SKILL;
    }
}
