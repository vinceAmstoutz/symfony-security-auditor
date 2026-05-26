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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\History\Exception;

use InvalidArgumentException;

final class InvalidHistoryDirectoryException extends InvalidArgumentException
{
    public static function forEmptyDir(): self
    {
        return new self('Audit history directory cannot be empty');
    }
}
