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
final readonly class AuthenticatorAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::AUTHENTICATOR;
    }

    #[Override]
    public function priority(): int
    {
        return 40;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="authenticator">
            Hunt:
            - `authenticate()` returning a `SelfValidatingPassport` for password-bearing flows (skips credential check → auth bypass).
            - `supports()` returning `null` instead of `false` for unsupported requests — `null` means "supports", silently letting non-matching paths through.
            - `onAuthenticationSuccess()` calling `RedirectResponse` with a user-controlled `_target_path` / `referer` without protocol+host allowlist.
            - `AccessTokenHandler::getUserBadgeFrom($accessToken)` not verifying signature/audience/issuer of JWT/opaque tokens.
            - Custom `LoginFormAuthenticator` storing the password in the session, log, or exception trace.
            - Missing `CsrfTokenBadge` on form-based login authenticators where CSRF was previously enforced.
            - OAuth/OIDC handlers omitting `state` parameter verification (CSRF on auth callback) or PKCE for public clients.
            - `UserBadge::setUserLoader()` query running with a user-controlled `identifier` without normalization (`User WHERE email = :id` accepting wildcards/case-insensitive variants).
            - `RememberMeBadge` attached unconditionally — not gated on a user-submitted "remember me" request parameter — issuing a long-lived authentication cookie for every login regardless of consent.
            Do NOT flag:
            - Authenticators that explicitly throw `AuthenticationException` on missing credentials.
            - `RememberMeBadge` conditionally attached based on a user-submitted "remember me" flag — that is the documented opt-in pattern.
            </skills>
            SKILL;
    }
}
