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
 * Composer/Packagist package names are conventionally lowercase, but nothing
 * stops an attacker LLM from echoing a capitalized `use` statement's
 * namespace-derived guess (`Symfony/Http-Foundation`) back as a
 * `lookup_advisory` tool argument. Normalizing both the stored keys and the
 * lookup query the same way lets a plausible but differently-cased or
 * padded package name still match a real, cached advisory.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PackageNameNormalizer
{
    public static function normalize(string $packageName): string
    {
        return strtolower(trim($packageName));
    }
}
