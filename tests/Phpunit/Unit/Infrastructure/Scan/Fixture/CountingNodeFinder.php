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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan\Fixture;

use Override;
use PhpParser\NodeFinder;

/**
 * Test fake: a real node finder that counts every node under the trees it is
 * asked to search, so a test can bound how many times a parser walks a syntax
 * tree without timing it.
 */
final class CountingNodeFinder extends NodeFinder
{
    public int $visitedNodes = 0;

    #[Override]
    public function findInstanceOf($nodes, string $class): array
    {
        $this->visitedNodes += \count(parent::find($nodes, static fn (): bool => true));

        return parent::findInstanceOf($nodes, $class);
    }
}
