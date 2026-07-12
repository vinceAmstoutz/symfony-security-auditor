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
final readonly class EventSubscriberAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::EVENT_SUBSCRIBER;
    }

    #[Override]
    public function priority(): int
    {
        return 80;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="event_subscriber">
            Hunt:
            - `KernelEvents::CONTROLLER` / `KernelEvents::REQUEST` subscribers mutating `$event->getRequest()->attributes` to inject privileged values (role, user id) before the controller runs.
            - `AuthenticationEvents::AUTHENTICATION_SUCCESS` listeners auto-elevating roles based on payload fields without re-checking the source.
            - `kernel.exception` listeners leaking stack traces, env vars, or internal hostnames in the response body.
            - Subscribers calling `Process` / making HTTP requests with values from the event (SSRF via event payload).
            - Listeners with side effects (DB write, mailer send) NOT wrapped in a Doctrine transaction or messenger envelope — request fails mid-way, state diverges.
            - Doctrine `postLoad` / `postFlush` events writing user-derived fields back without escaping (stored XSS, log injection).
            Do NOT flag:
            - Subscribers using `$event->setResponse()` to short-circuit — that is the documented kernel.controller pattern.
            - Listeners calling `LoggerInterface::info()` with structured arrays — not log injection unless raw `$_REQUEST` is interpolated.
            </skills>
            SKILL;
    }
}
