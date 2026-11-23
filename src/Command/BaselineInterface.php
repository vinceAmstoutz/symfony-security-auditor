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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\BaselineWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;

/** @internal not part of the BC promise, see docs/versioning.md */
interface BaselineInterface
{
    /**
     * The accepted fingerprints of a baseline file, none for a missing file. A
     * malformed file throws.
     *
     * @return list<string>
     */
    public function load(string $path): array;

    /**
     * The entries of a baseline file with their raw payloads, none for a
     * missing file. A malformed file throws.
     *
     * @return list<BaselineEntry>
     */
    public function entries(string $path): array;

    /**
     * The entries of a baseline file that carry a non-empty `reason`, none for
     * a missing file. A malformed file throws.
     */
    public function feedback(string $path): ReviewerFeedback;

    /**
     * Refuses a path the baseline could never be saved to.
     *
     * @param string $projectPath the audited project, whose directories are walked for a symlink like the working directory's
     *
     * @throws UnsafeBaselineWriteException
     * @throws BaselineWriteFailedException
     */
    public function assertWritable(string $path, string $projectPath): void;

    /**
     * @param list<array<array-key, mixed>|string> $entries     each a map holding at least a `fingerprint`, or a bare fingerprint
     * @param ?string                              $projectPath the audited project, whose directories are walked for a symlink like the working directory's; null outside an audit run
     */
    public function save(string $path, array $entries, ?string $projectPath = null): void;
}
