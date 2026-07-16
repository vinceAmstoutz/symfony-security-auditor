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
final readonly class TrustBoundaryAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::CONFIG;
    }

    #[Override]
    public function priority(): int
    {
        return 155;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="trust_boundary">
            Hunt (`framework.trusted_proxies` / `framework.trusted_headers` / `TRUSTED_PROXIES`):
            - `trusted_proxies` set to a wildcard CIDR (`'0.0.0.0/0'`, `'::/0'`) — any client can spoof `X-Forwarded-For`/`X-Forwarded-Host`/`X-Forwarded-Proto`, defeating IP allowlists and rate limiters that trust `Request::getClientIp()`.
            - `TRUSTED_PROXIES=0.0.0.0/0` (or an equivalent wildcard) in a committed `.env`/`.env.*` file — same risk, sourced from the environment instead of YAML.
            - `framework.trusted_hosts` absent or empty while the app builds absolute URLs (password-reset links, email-verification links, webhook callback URLs) from the incoming request — an attacker-supplied `Host` header is trusted verbatim and can poison those links or an intermediary cache.
            Do NOT flag:
            - `trusted_proxies` scoped to a private/internal CIDR (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or a specific load-balancer IP — that is the correct configuration for a reverse-proxy deployment.
            - `trusted_hosts` populated with an explicit allow-list of hostnames or a regex.
            </skills>
            SKILL;
    }
}
