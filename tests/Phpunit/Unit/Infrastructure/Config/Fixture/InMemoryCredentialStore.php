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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialStoreInterface;

final class InMemoryCredentialStore implements CredentialStoreInterface
{
    /**
     * @param array<string, string> $credentials
     */
    public function __construct(private array $credentials = []) {}

    #[Override]
    public function read(string $variableName): ?string
    {
        return $this->credentials[$variableName] ?? null;
    }

    #[Override]
    public function write(string $variableName, string $credential): void
    {
        $this->credentials[$variableName] = $credential;
    }

    #[Override]
    public function remove(string $variableName): bool
    {
        if (!\array_key_exists($variableName, $this->credentials)) {
            return false;
        }

        unset($this->credentials[$variableName]);

        return true;
    }

    #[Override]
    public function location(): ?string
    {
        return '/tmp/in-memory/credentials.json';
    }
}
