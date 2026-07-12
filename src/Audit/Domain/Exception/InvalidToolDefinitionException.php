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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception;

use InvalidArgumentException;

final class InvalidToolDefinitionException extends InvalidArgumentException
{
    public static function forBlankName(): self
    {
        return new self('Tool name cannot be empty');
    }

    public static function forBlankDescription(): self
    {
        return new self('Tool description cannot be empty');
    }
}
