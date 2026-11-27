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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

/**
 * The subscription a run was billed to, as the coding agent's CLI named it
 * before the run, without the account that could identify a person. Unset
 * until a run checks it, or when the CLI could not tell.
 *
 * Not readonly: the subscription is set after construction. A late-bound
 * holder per .claude/rules/php-classes.md.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class BilledSubscriptionHolder
{
    private ?string $billedSubscription = null;

    /**
     * Takes null when the latest run could not tell which subscription it bills.
     */
    public function set(?string $billedSubscription): void
    {
        $this->billedSubscription = $billedSubscription;
    }

    public function billedSubscription(): ?string
    {
        return $this->billedSubscription;
    }
}
