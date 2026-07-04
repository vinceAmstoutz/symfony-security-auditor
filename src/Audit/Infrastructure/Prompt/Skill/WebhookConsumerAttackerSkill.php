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
final readonly class WebhookConsumerAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::WEBHOOK_CONSUMER;
    }

    #[Override]
    public function priority(): int
    {
        return 60;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="webhook_consumer">
            Hunt:
            - `RequestParserInterface::parse()` / `RemoteEventConsumerInterface::consume()` consuming the payload without HMAC / signature verification (`hash_equals` with the configured secret).
            - Signature compared with `===` / `==` (timing-attack vulnerable) instead of `hash_equals()`.
            - Missing replay-attack defense: no nonce check, no timestamp check, no idempotency key — same payload can be replayed indefinitely.
            - `#[AsRemoteEventConsumer]` handler trusting `$payload['user_id']` / `$payload['amount']` without re-validating against the authenticated source.
            - JSON / XML parsers without bounded depth/size (DoS via large or deeply-nested payloads).
            - Webhook routes mounted under a firewall that allows anonymous access AND lacks IP allowlist or mutual-TLS gating.
            Do NOT flag:
            - Webhook handlers calling `hash_equals($expected, $received)` against the framework's secret.
            - `WebhookComponent::validate($request, $secret)` invocations — those use constant-time comparison internally.
            </skills>
            SKILL;
    }
}
