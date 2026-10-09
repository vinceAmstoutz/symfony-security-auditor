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
use Symfony\Component\Config\Definition\StringNode;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class NullableStringNode extends StringNode
{
    #[Override]
    protected function validateType(mixed $value): void
    {
        if (null !== $value) {
            parent::validateType($value);
        }
    }

    #[Override]
    protected function isValueEmpty(mixed $value): bool
    {
        return null !== $value && parent::isValueEmpty($value);
    }
}
