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

final class InvalidAuditContextException extends InvalidArgumentException
{
    public static function forInvalidProjectPath(string $projectPath): self
    {
        return new self(\sprintf('Project path "%s" is not a valid directory', $projectPath));
    }
}
