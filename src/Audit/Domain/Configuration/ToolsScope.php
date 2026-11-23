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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration;

/**
 * Which files the `read_file`, `grep` and `list_files` tools may open.
 *
 * - `audited` (the default): only the files the run audits, so a narrowed run
 *   sends the provider no other source.
 * - `scanned`: every file the scan found, so a narrowed run can follow a file
 *   to the unchanged code it depends on.
 */
enum ToolsScope: string
{
    case Audited = 'audited';
    case Scanned = 'scanned';
}
