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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval;

/**
 * One seeded ground-truth vulnerability the auditor is expected to find,
 * identified by the file it lives in and its vulnerability type.
 */
final readonly class ExpectedFinding
{
    public function __construct(
        public string $file,
        public string $type,
    ) {}

    public function key(): string
    {
        return \sprintf('%s::%s', $this->file, $this->type);
    }
}
