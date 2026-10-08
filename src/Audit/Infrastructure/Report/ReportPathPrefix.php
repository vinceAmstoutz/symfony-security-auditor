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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

use function Symfony\Component\String\u;

/**
 * The folder, relative to the repository root, the audited project lives in
 * (`audit.report_path_prefix`). A finding's path is relative to the project, but
 * the formats a repository host reads — SARIF locations, GitHub annotations —
 * are resolved from the repository root, so a project in a sub-folder needs the
 * folder put in front of every path for an alert to land on its file.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReportPathPrefix
{
    private string $prefix;

    public function __construct(?string $prefix = null)
    {
        $folder = u($prefix)->trim()->replace('\\', '/')->trim('/');
        while ($folder->startsWith('./')) {
            $folder = $folder->after('/');
        }

        $this->prefix = '.' === $folder->toString() ? '' : $folder->toString();
    }

    public function apply(string $filePath): string
    {
        return '' === $this->prefix ? $filePath : \sprintf('%s/%s', $this->prefix, $filePath);
    }
}
