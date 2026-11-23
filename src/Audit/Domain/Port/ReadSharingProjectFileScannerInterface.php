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
 * Optional companion of {@see ProjectFileScannerInterface}: shares what it
 * read between several scans, so a file the configured surface and a `--path`
 * value both reach is read and scrubbed once.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
