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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;

/**
 * The cost a report shows: the subscription a run was billed to once it is
 * known, the dollar estimate and how it was priced otherwise.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CostLine
{
    public static function of(AuditCost $auditCost, ?string $subscription, ?string $billedSubscription): string
    {
        return null === $billedSubscription
            ? \sprintf('$%s (%s)', number_format($auditCost->estimatedCostUsd(), 4, '.', ''), CostRateLabel::of($auditCost, $subscription))
            : \sprintf('billed to %s', $billedSubscription);
    }
}
