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
final readonly class ControllerTrustBoundaryAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::CONTROLLER;
    }

    #[Override]
    public function priority(): int
    {
        return 17;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="controller_trust_boundary">
            Hunt (`Request::getHost()` / `getSchemeAndHttpHost()` / `getHttpHost()`):
            - The Host derived from the request is used to build a password-reset, email-verification, or webhook-callback URL without a hardcoded or `%env(APP_URL)%`-sourced base — an attacker-controlled `Host` header ends up embedded in a link sent to another user (host header injection / password-reset poisoning).
            - A cache key, cached response, or `Cache-Control` decision derived from the request's Host or forwarded headers — HTTP cache poisoning via header spoofing when `trusted_proxies`/`trusted_hosts` is not correctly scoped.
            Do NOT flag:
            - URL generation via the `router` service (`UrlGeneratorInterface::generate(..., UrlGeneratorInterface::ABSOLUTE_URL)`) — Symfony's router uses the configured request context, not a manually read `Host` header.
            - `getHost()`/`getHttpHost()` calls used only for logging or display, not for building a link, cache key, or security decision.
            </skills>
            SKILL;
    }
}
