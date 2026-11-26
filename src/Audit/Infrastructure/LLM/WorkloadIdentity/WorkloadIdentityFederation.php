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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity;

/**
 * The Anthropic workload identity federation rule an identity token is
 * exchanged under.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class WorkloadIdentityFederation
{
    private const string JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    public function __construct(
        public string $ruleId,
        public string $organizationId,
        public ?string $serviceAccountId = null,
        public ?string $workspaceId = null,
    ) {}

    /**
     * @return array<string, string>
     */
    public function exchangeRequest(string $identityToken): array
    {
        return array_filter([
            'grant_type' => self::JWT_BEARER_GRANT,
            'assertion' => $identityToken,
            'federation_rule_id' => $this->ruleId,
            'organization_id' => $this->organizationId,
            'service_account_id' => $this->serviceAccountId,
            'workspace_id' => $this->workspaceId,
        ], static fn (?string $value): bool => null !== $value);
    }
}
