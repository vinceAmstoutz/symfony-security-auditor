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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * One gap the coverage critic named: the audited files no chunk showed
 * together, what it suspects they let an attacker do, and the attack class to
 * look for. The attacker analyzes the files as one chunk led by the hypothesis.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CoverageGap
{
    /**
     * @param list<ProjectFile> $files
     */
    public function __construct(
        public array $files,
        public string $hypothesis,
        public string $attackClass,
    ) {}
}
