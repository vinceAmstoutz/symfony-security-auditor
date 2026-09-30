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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

/**
 * What a JSON audit report tells a comparison: its findings, and the files it
 * could not fully analyze — where the absence of a finding proves nothing.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LoadedReport
{
    /**
     * @param list<DiffFinding> $findings
     * @param list<string>      $unanalyzedFiles
     */
    public function __construct(
        public array $findings,
        public array $unanalyzedFiles = [],
    ) {}
}
