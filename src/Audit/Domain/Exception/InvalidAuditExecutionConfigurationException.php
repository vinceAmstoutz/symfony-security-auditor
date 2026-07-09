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

final class InvalidAuditExecutionConfigurationException extends InvalidArgumentException
{
    public static function forOutOfRangeMinConfidence(float $minConfidence): self
    {
        return new self(\sprintf('minConfidence must be finite and within 0.0-1.0, got %s', $minConfidence));
    }
}
