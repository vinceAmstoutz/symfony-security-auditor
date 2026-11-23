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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

/**
 * The form both the stored advisory keys and a lookup are compared in, so
 * `Symfony/Http-Foundation` from the model matches `symfony/http-foundation`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PackageNameNormalizer
{
    public static function normalize(string $packageName): string
    {
        return strtolower(trim($packageName));
    }
}
