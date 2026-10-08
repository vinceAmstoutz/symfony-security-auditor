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
use Symfony\Component\Config\Definition\Builder\FloatNodeDefinition;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class NullableFloatNodeDefinition extends FloatNodeDefinition
{
    #[Override]
    protected function instantiateNode(): NullableFloatNode
    {
        return new NullableFloatNode($this->name, $this->parent, $this->min, $this->max, $this->pathSeparator);
    }
}
