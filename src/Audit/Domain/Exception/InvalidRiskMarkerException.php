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

final class InvalidRiskMarkerException extends InvalidArgumentException
{
    public static function forBlankFilePath(): self
    {
        return new self('File path cannot be empty');
    }

    public static function forNonPositiveLine(): self
    {
        return new self('Line number must be >= 1');
    }

    public static function forBlankPattern(): self
    {
        return new self('Pattern label cannot be empty');
    }
}
