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

use Composer\InstalledVersions;
use OutOfBoundsException;

/** @internal shared package identity used across report renderers */
final readonly class ReportPackage
{
    public const string NAME = 'vinceamstoutz/symfony-security-auditor';

    public const string HOMEPAGE_URL = 'https://github.com/vinceamstoutz/symfony-security-auditor';

    public const string UNKNOWN_VERSION = 'unknown';

    public function __construct(
        private string $packageName = self::NAME,
    ) {}

    public function version(): string
    {
        try {
            return InstalledVersions::getPrettyVersion($this->packageName) ?? self::UNKNOWN_VERSION;
        } catch (OutOfBoundsException) {
            return self::UNKNOWN_VERSION;
        }
    }
}
