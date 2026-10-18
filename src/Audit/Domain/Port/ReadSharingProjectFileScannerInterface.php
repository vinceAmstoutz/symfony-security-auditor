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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

/**
 * Opt-in companion of {@see ProjectFileScannerInterface} for a scanner that can
 * share what it read between several scans: a run scans its configured surface
 * and its `--path` values through one such scanner, so a file both reach is
 * read and scrubbed once.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ReadSharingProjectFileScannerInterface extends ProjectFileScannerInterface
{
    /**
     * A scanner applying the same rules that reads and scrubs each file once,
     * however many of its scans reach it. It never reads a file again, so it
     * serves the scans of one run only.
     */
    public function sharingReads(): ProjectFileScannerInterface;
}
