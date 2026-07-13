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

use InvalidArgumentException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class InsufficientTrendReportsException extends InvalidArgumentException
{
    public static function forCount(int $count): self
    {
        return new self(\sprintf('A trend needs at least two report files ordered oldest to newest, got %d.', $count));
    }
}
