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
final readonly class LdapServiceAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::LDAP_SERVICE;
    }

    #[Override]
    public function priority(): int
    {
        return 42;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="ldap_service">
            Hunt:
            - An LDAP filter string built with `sprintf()`/string concatenation from request or form input, then passed to `Ldap::query()` / `ldap_search()` without escaping — LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) let an attacker widen or rewrite the filter (LDAP injection).
            - A DN (distinguished name) built by concatenating user input directly (e.g. `"uid={$username},ou=..."`) — the same metacharacter class lets the value break out of the intended DN scope.
            - `Ldap::bind()` called with a password that could be an empty string — most LDAP/Active Directory servers treat an empty password as an unauthenticated (anonymous) bind that still succeeds, silently bypassing the credential check.
            - Filter or DN values interpolated without `ldap_escape()` first.
            Do NOT flag:
            - Filter/DN values built exclusively from server-side constants, or already passed through `ldap_escape()` before interpolation.
            </skills>
            SKILL;
    }
}
