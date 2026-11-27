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

/** @internal not part of the BC promise, see docs/versioning.md */
interface IdentityTokenSourceInterface
{
    /**
     * Returns a fresh OIDC identity token of the workload, the assertion the
     * federation rule trusts.
     */
    public function identityToken(): string;
}
