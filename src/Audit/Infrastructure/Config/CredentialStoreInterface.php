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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;

/**
 * Per-user storage for provider API keys, keyed by the environment variable
 * the configuration names, so a machine the user has set up once no longer
 * needs the key exported into every shell.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface CredentialStoreInterface
{
    /**
     * @throws UnreadableCredentialStoreException
     */
    public function read(string $variableName): ?string;

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function write(string $variableName, string $credential): void;

    /**
     * @return bool whether a credential was actually stored under that name
     *
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function remove(string $variableName): bool;

    /**
     * @return string|null the file credentials are kept in, or null when no
     *                     per-user configuration directory can be resolved
     */
    public function location(): ?string;
}
