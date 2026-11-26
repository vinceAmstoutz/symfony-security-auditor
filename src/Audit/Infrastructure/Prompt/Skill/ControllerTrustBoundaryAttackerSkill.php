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

/** @internal not part of the BC promise, see docs/versioning.md */
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
            Hunt (`Request::getHost()` / `getSchemeAndHttpHost()` / `getHttpHost()` / `UrlGeneratorInterface::ABSOLUTE_URL`):
            - The Host derived from the request is used to build a password-reset, email-verification, or webhook-callback URL without a hardcoded or `%env(APP_URL)%`-sourced base — an attacker-controlled `Host` header ends up embedded in a link sent to another user (host header injection / password-reset poisoning).
            - A password-reset, email-verification or invitation link built during a request, by `generateUrl()` or `UrlGeneratorInterface::generate()` with `UrlGeneratorInterface::ABSOLUTE_URL` in the PHP that handles the request and returns or sends the link, or by Twig's `url()` in a template that request renders, while `framework.trusted_hosts` is not set: the router takes the link's host from the request's `Host` header, so the attacker picks where it points. Report as `host_header_injection`. Unless you can see that `framework.trusted_hosts` is unset, in a configuration file of the chunk or one you read, set `confidence` no higher than 0.6 and name that unverified setting in `attack_vector`.
            - A cache key, cached response, or `Cache-Control` decision derived from the request's Host or forwarded headers — HTTP cache poisoning via header spoofing when `trusted_proxies`/`trusted_hosts` is not correctly scoped.
            Do NOT flag:
            - An absolute URL the router builds outside an HTTP request (a console command, a message consumed asynchronously, a scheduled task), where its host comes from `framework.router.default_uri`, or while `framework.trusted_hosts` lists the application's hosts.
            - Twig's `url()` in the template of a `TemplatedEmail`, unless the code handling the request visibly renders that template itself (`renderView()`, `Environment::render()`): a mail sent through Messenger is rendered by the worker, where `framework.router.default_uri` applies.
            - `getHost()`/`getHttpHost()` calls used only for logging or display, not for building a link, cache key, or security decision.
            </skills>
            SKILL;
    }
}
