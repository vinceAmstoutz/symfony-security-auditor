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
 * configuration directory.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
        $this->guardAgainstInsecurePermissions();

        $credential = $this->credentials()[$variableName] ?? '';

        return '' !== $credential ? $credential : null;
    }

    #[Override]
    public function write(string $variableName, string $credential): void
    {
        $this->guardAgainstUnstorableVariableName($variableName);
        $this->guardAgainstUnstorableCredential($credential);

        $credentials = $this->credentials(replaceMalformed: true);
        $credentials[$variableName] = $credential;

        $this->persist($credentials);
    }

    #[Override]
    public function remove(string $variableName): bool
    {
        $credentials = $this->credentials();
        if (!\array_key_exists($variableName, $credentials)) {
            return false;
        }

        unset($credentials[$variableName]);
        $this->persist($credentials);

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
    private function credentials(bool $replaceMalformed = false): array
    {
        $path = $this->location();
        if (null === $path || !$this->filesystem->exists($path)) {
            return [];
        }

        $raw = $this->rawContent($path);

        return '' !== $raw ? $this->decodeOrReplace($path, $raw, $replaceMalformed) : [];
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    private function rawContent(string $path): string
    {
        try {
            return trim($this->filesystem->readFile($path));
        } catch (IOException) {
            throw UnreadableCredentialStoreException::forUnreadableFile($path);
        }
    }

    /**
     * With `$replaceMalformed`, returns no credential for content that does
     * not parse instead of throwing.
     *
     * @return array<string, string>
     *
     * @throws UnreadableCredentialStoreException
     */
    private function decodeOrReplace(string $path, string $raw, bool $replaceMalformed): array
    {
        if (!$replaceMalformed) {
            return $this->decode($path, $raw);
        }

        try {
            return $this->decode($path, $raw);
        } catch (UnreadableCredentialStoreException) {
            return [];
        }
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
     * Refuses a file other users can open; a write restores the mode instead.
     * Checks nothing on Windows, where the file inherits the user-profile ACL
     * of `%APPDATA%`.
     *
     * @throws UnreadableCredentialStoreException
     */
    private function guardAgainstInsecurePermissions(): void
    {
        $path = $this->location();
        if (null === $path || !$this->filesystem->exists($path) || self::WINDOWS_OS_FAMILY === $this->osFamily) {
            return;
        }

        $permissions = fileperms($path);
        if (false === $permissions || 0 === ($permissions & self::GROUP_AND_OTHER_BITS)) {
            return;
        }

        throw UnreadableCredentialStoreException::forInsecurePermissions($path, $permissions & self::PERMISSION_BITS);
    }

    /**
     * Refuses a name no `%env()%` placeholder can read back.
     *
     * @throws CredentialStoreWriteException
     */
    private function guardAgainstUnstorableVariableName(string $variableName): void
    {
        if (!EnvironmentVariableName::isValid($variableName)) {
            throw CredentialStoreWriteException::forInvalidVariableName($variableName);
        }
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
     * @param array<string, string> $credentials
     *
     * @throws CredentialStoreWriteException
     */
    private function persist(array $credentials): void
    {
        $path = $this->location();
        if (null === $path) {
            throw CredentialStoreWriteException::forUnresolvableLocation();
        }

        $payload = json_encode($credentials);
        \assert(false !== $payload, 'A map of validated names to UTF-8 validated strings is always JSON-encodable');

        try {
            $this->createOwnerOnly($path);
            $this->filesystem->dumpFile($path, $payload);
        } catch (IOException $ioException) {
            throw CredentialStoreWriteException::forPath($path, $ioException);
        }
    }

    /**
     * Makes the directory and then the file owner-only before any credential
     * is written: `dumpFile()` would create the file with the umask.
     *
     * @throws IOException
     */
    private function createOwnerOnly(string $path): void
    {
        $directory = \dirname($path);
        $this->filesystem->mkdir($directory);
        $this->filesystem->chmod($directory, self::DIRECTORY_MODE);

        if (!$this->filesystem->exists($path)) {
            $this->filesystem->dumpFile($path, '');
        }

        $this->filesystem->chmod($path, self::FILE_MODE);
    }
}
