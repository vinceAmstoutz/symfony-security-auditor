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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command\Fixture;

use Generator;
use IteratorAggregate;
use Override;

/**
 * Test fake: the file paths of a baseline, counting every path read from
 * them, so a test can bound how many times the baseline is walked without
 * timing it.
 *
 * @implements IteratorAggregate<int, string>
 */
final class CountingFilePaths implements IteratorAggregate
{
    public int $readPaths = 0;

    /**
     * @param list<string> $filePaths
     */
    public function __construct(
        private readonly array $filePaths,
    ) {}

    #[Override]
    public function getIterator(): Generator
    {
        foreach ($this->filePaths as $filePath) {
            ++$this->readPaths;

            yield $filePath;
        }
    }
}
