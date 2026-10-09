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
use Symfony\Component\Config\Definition\Builder\IntegerNodeDefinition;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class NullableIntegerNodeDefinition extends IntegerNodeDefinition
{
    #[Override]
    protected function instantiateNode(): NullableIntegerNode
    {
        return new NullableIntegerNode($this->name, $this->parent, $this->min, $this->max, $this->pathSeparator);
    }
}
