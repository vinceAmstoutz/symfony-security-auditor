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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;

/**
 * Stores nothing: the bundle reads credentials from the application's own
 * environment.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class NullCredentialStore implements CredentialStoreInterface
{
    /**
     * @throws void
     */
    #[Override]
    public function read(string $variableName): ?string
    {
        return null;
    }

    /**
     * @throws CredentialStoreWriteException
     */
    #[Override]
    public function write(string $variableName, string $credential): void
    {
        throw CredentialStoreWriteException::forUnresolvableLocation();
    }

    /**
     * @throws void
     */
    #[Override]
    public function remove(string $variableName): bool
    {
        return false;
    }

    #[Override]
    public function location(): ?string
    {
        return null;
    }
}
