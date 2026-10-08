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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class UnenforceableBudgetException extends RuntimeException
{
    /** @param list<string> $unpricedModels */
    public static function forUnpricedModels(array $unpricedModels): self
    {
        return new self(\sprintf(
            'Refusing to start a budgeted audit with an unpriceable model in non-interactive mode. Configure a model with published pricing, or remove audit.budget.max_cost_usd. Unpriced model(s): %s.',
            implode(', ', $unpricedModels),
        ));
    }
}
