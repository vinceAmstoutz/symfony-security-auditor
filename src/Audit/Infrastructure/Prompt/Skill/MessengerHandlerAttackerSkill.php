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
final readonly class MessengerHandlerAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::MESSENGER_HANDLER;
    }

    #[Override]
    public function priority(): int
    {
        return 70;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="messenger_handler">
            Hunt:
            - `#[AsMessageHandler]` / `MessageHandlerInterface::__invoke()` calling `unserialize()` / `igbinary_unserialize()` on payload fields.
            - Handlers invoking `Process` / `shell_exec` / SQL with values from `$message` without sanitization (queue-to-shell injection).
            - Missing idempotency: handler with side effects (charge card, send email, mutate balance) not deduping by message id (`AmqpStamp::getAttributes()['headers']['x-message-id']`).
            - No replay protection: handler trusts `$message->createdAt` / `$message->userId` without verifying current state (stale message attack).
            - Transport configured with `serializer: php` (PHP-native serialize on untrusted bus) — gadget-chain RCE.
            - Handler swallowing exceptions silently → poisoned messages re-driven infinitely.
            - Privileged action triggered solely by message presence with no authorization (`InvalidateUserCommand`, `PromoteToAdmin`, etc.).
            Do NOT flag:
            - Handlers using the default `JsonSerializer` transport — well-typed via Symfony Serializer.
            - Handlers using `Symfony\Component\Messenger\Stamp\BusNameStamp` / `TransportNamesStamp` — those are routing, not security smells.
            </skills>
            SKILL;
    }
}
