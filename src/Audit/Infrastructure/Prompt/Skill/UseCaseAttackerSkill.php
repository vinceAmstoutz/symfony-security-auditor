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
final readonly class UseCaseAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::USE_CASE;
    }

    #[Override]
    public function priority(): int
    {
        return 65;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="use_case">
            Hunt:
            - A command or query handler, use case or interactor that changes state or returns another user's or tenant's data with no authorization of its own while a caller in the chunk checks nothing either (an unguarded action, a console command, a Messenger route, an API Platform processor, another handler) — in a clean or hexagonal architecture the use case is the last place the rule can live.
            - The acting user or tenant read from the command or query itself (`$command->userId`, `$query->tenantId`) while that message is built from request data (`#[MapRequestPayload]` straight into the command, `$serializer->deserialize($request->getContent(), …)`) — the client picks whose record changes.
            - A handler authorizing through `Security::getUser()` or the token storage and skipping the check when no user is present (`if ($user && …)`) — routed to an async transport or run from the console it executes with no token, so a `null` user must deny.
            - A generic bus endpoint resolving the message class from input (`$serializer->deserialize($body, $request->get('type'), 'json')` then `$bus->dispatch()`, `new $class(...)`) — any command, privileged ones included, can be dispatched.
            - {requires api-platform/core|api-platform/symfony|api-platform/state} An API Platform state processor saving the denormalized `$data` while its operation checks only `security` (evaluated before the client's changes) and not `securityPostDenormalize` — the client rewrites the owner or tenant of an object it may edit; a state provider loading by `$uriVariables` with no ownership check is an IDOR.
            - Authorization or validation left to a bus middleware that only handles messages carrying a marker interface or attribute, or that sits on one bus only — a privileged command without the marker, or dispatched on another bus, skips it.
            - A query handler fetching by id (`find($query->id)`, `getById()`) without scoping to the caller, or building SQL from query fields (`ORDER BY {$query->sort}`, DBAL `executeQuery()` with concatenated filters) on the read side. Report as `sql_injection` when input reaches the SQL text.
            - Check-then-act on a balance, stock or quota inside a handler with no lock, transaction or version check — concurrent commands double-spend. Report as `race_condition`.
            Do NOT flag:
            - A handler whose caller in the chunk enforces the same rule (a voter-guarded action that sets the actor from `$this->getUser()`), or whose bus runs an authorization middleware covering the message.
            - An actor id on the command set by server code from the authenticated user, never read from the request.
            - Query handlers returning public data (catalog, published content).
            </skills>
            SKILL;
    }
}
