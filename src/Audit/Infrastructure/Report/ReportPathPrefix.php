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
 * The folder of the audited project relative to the repository root
 * (`audit.report_path_prefix`), put before every path of the formats a
 * repository host resolves from its root: SARIF and GitHub annotations.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
