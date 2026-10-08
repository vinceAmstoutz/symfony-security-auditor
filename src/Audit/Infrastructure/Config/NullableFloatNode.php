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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use Override;
use Symfony\Component\Config\Definition\FloatNode;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class NullableFloatNode extends FloatNode
{
    #[Override]
    protected function validateType(mixed $value): void
    {
        if (null !== $value) {
            parent::validateType($value);
        }
    }

    #[Override]
    protected function finalizeValue(mixed $value): mixed
    {
        return null === $value ? null : parent::finalizeValue($value);
    }
}
