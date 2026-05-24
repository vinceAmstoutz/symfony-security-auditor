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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class BudgetExceededException extends RuntimeException
{
    public static function forTokens(int $used, int $cap): self
    {
        return new self(\sprintf('Audit aborted: token budget exceeded (%d / %d tokens)', $used, $cap));
    }

    public static function forCost(float $used, float $cap): self
    {
        return new self(\sprintf('Audit aborted: cost budget exceeded ($%.4f / $%.4f USD)', $used, $cap));
    }
}
