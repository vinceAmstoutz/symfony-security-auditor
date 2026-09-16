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

use JsonException;
use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;

/**
 * Keeps provider API keys in an owner-only JSON file under the per-user
 * configuration directory. Reading refuses a file other users on the machine
 * can open, on the reasoning that a credential exposed once is a credential to
 * rotate rather than one to keep using.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FilesystemCredentialStore implements CredentialStoreInterface
{
    private const int FILE_MODE = 0600;

    private const int DIRECTORY_MODE = 0700;

    private const int GROUP_AND_OTHER_BITS = 0077;

    private const int PERMISSION_BITS = 0777;

    private const string WINDOWS_OS_FAMILY = 'Windows';

    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private Filesystem $filesystem = new Filesystem(),
        private string $osFamily = \PHP_OS_FAMILY,
    ) {}

    #[Override]
    public function read(string $variableName): ?string
    {
        $credential = $this->credentials()[$variableName] ?? '';

        return '' !== $credential ? $credential : null;
    }

    #[Override]
    public function write(string $variableName, string $credential): void
    {
        $this->guardAgainstUnstorableCredential($credential);

        $path = $this->securedPath();
        $credentials = $this->credentials();
        $credentials[$variableName] = $credential;

        $this->persist($path, $credentials);
    }

    #[Override]
    public function remove(string $variableName): bool
    {
        $path = $this->securedPath();
        $credentials = $this->credentials();
        if (!\array_key_exists($variableName, $credentials)) {
            return false;
        }

        unset($credentials[$variableName]);
        $this->persist($path, $credentials);

        return true;
    }

    #[Override]
    public function location(): ?string
    {
        try {
            return $this->xdgConfigPathResolver->credentialsFile();
        } catch (UnresolvableConfigPathException) {
            return null;
        }
    }

    /**
     * @return array<string, string>
     *
     * @throws UnreadableCredentialStoreException
     */
    private function credentials(): array
    {
        $path = $this->location();
        if (null === $path || !$this->filesystem->exists($path)) {
            return [];
        }

        $this->guardAgainstInsecurePermissions($path);

        try {
            $raw = trim($this->filesystem->readFile($path));
        } catch (IOException) {
            throw UnreadableCredentialStoreException::forUnreadableFile($path);
        }

        return '' !== $raw ? $this->decode($path, $raw) : [];
    }

    /**
     * @return array<string, string>
     *
     * @throws UnreadableCredentialStoreException
     */
    private function decode(string $path, string $raw): array
    {
        try {
            $decoded = json_decode($raw, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw UnreadableCredentialStoreException::forMalformedContent($path);
        }

        if (!\is_array($decoded)) {
            throw UnreadableCredentialStoreException::forMalformedContent($path);
        }

        $credentials = [];
        foreach ($decoded as $name => $credential) {
            if (\is_string($name) && \is_string($credential)) {
                $credentials[$name] = $credential;
            }
        }

        return $credentials;
    }

    /**
     * Windows has no POSIX permission bits — `fileperms()` reports the same
     * mode for every file on an NTFS volume — so the file there is protected
     * by the user-profile ACL it inherits from `%APPDATA%` instead.
     *
     * @throws UnreadableCredentialStoreException
     */
    private function guardAgainstInsecurePermissions(string $path): void
    {
        if (self::WINDOWS_OS_FAMILY === $this->osFamily) {
            return;
        }

        $permissions = ((int) fileperms($path)) & self::PERMISSION_BITS;
        if (0 === ($permissions & self::GROUP_AND_OTHER_BITS)) {
            return;
        }

        throw UnreadableCredentialStoreException::forInsecurePermissions($path, $permissions);
    }

    /**
     * @throws CredentialStoreWriteException
     */
    private function guardAgainstUnstorableCredential(string $credential): void
    {
        if ('' === $credential) {
            throw CredentialStoreWriteException::forBlankCredential();
        }

        if (1 !== preg_match('//u', $credential)) {
            throw CredentialStoreWriteException::forNonUtf8Credential();
        }
    }

    /**
     * Both mutating paths tighten the file before they read it, so a file
     * something else left world-readable can still be rewritten or emptied
     * from here — refusing would put the only recovery outside the tool, on
     * the one credential a user most needs to replace.
     *
     * @throws CredentialStoreWriteException
     */
    private function securedPath(): string
    {
        $path = $this->location();
        if (null === $path) {
            throw CredentialStoreWriteException::forUnresolvableLocation();
        }

        try {
            $this->createOwnerOnly($path);
        } catch (IOException $ioException) {
            throw CredentialStoreWriteException::forPath($path, $ioException);
        }

        return $path;
    }

    /**
     * @param array<string, string> $credentials
     *
     * @throws CredentialStoreWriteException
     */
    private function persist(string $path, array $credentials): void
    {
        $payload = json_encode($credentials);
        \assert(false !== $payload, 'A map of UTF-8 validated strings is always JSON-encodable');

        try {
            $this->filesystem->dumpFile($path, $payload);
        } catch (IOException $ioException) {
            throw CredentialStoreWriteException::forPath($path, $ioException);
        }
    }

    /**
     * `dumpFile()` gives a file it creates the process umask, so the file is
     * created empty and tightened before the credential is written into it —
     * the secret only ever reaches a path that is already owner-only.
     *
     * @throws IOException
     */
    private function createOwnerOnly(string $path): void
    {
        if (!$this->filesystem->exists($path)) {
            $this->filesystem->dumpFile($path, '');
        }

        $this->filesystem->chmod($path, self::FILE_MODE);
        $this->filesystem->chmod(\dirname($path), self::DIRECTORY_MODE);
    }
}
