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

/** @internal not part of the BC promise — see docs/versioning.md */
interface BaselineInterface
{
    /**
     * Loads the suppressed-finding fingerprints from a baseline file. A missing
     * file yields an empty list (nothing suppressed); a malformed file throws.
     *
     * @return list<string>
     */
    public function load(string $path): array;

    /**
     * Loads the entries of a baseline file with their raw decoded payloads
     * preserved, so a merge can rewrite the file without losing hand-written
     * keys such as `reason`. A missing file yields an empty list; a malformed
     * file throws.
     *
     * @return list<BaselineEntry>
     */
    public function entries(string $path): array;

    /**
     * Loads the maintainer-authored false-positive feedback from a baseline
     * file: every entry annotated with a non-empty `reason`. A missing file —
     * or one whose entries carry no reasons — yields empty feedback; a
     * malformed file throws.
     */
    public function feedback(string $path): ReviewerFeedback;

    /**
     * @param list<array<array-key, mixed>|string> $entries accepted-finding entries; each
     *                                                      carries at least a `fingerprint`
     *                                                      plus human-readable metadata
     *                                                      (`type`, `file`, `title`,
     *                                                      `added_at`) — or, for a legacy
     *                                                      entry, the bare fingerprint string
     */
    public function save(string $path, array $entries): void;
}
