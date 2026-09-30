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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialStoreInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;

/** @internal not part of the BC promise — the command *name* (`auth:status`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
final readonly class AuthStatusCommand
{
    public const string NAME = 'auth:status';

    public const string DESCRIPTION = 'Show which API key an audit would use, without printing it';

    private const string ENVIRONMENT_SOURCE = 'the environment';

    private const string STORE_SOURCE = 'stored on this machine';

    /**
     * @param array<string, string> $environment
     */
    public function __construct(
        private CredentialStoreInterface $credentialStore,
        private ConfiguredCredentialVariable $configuredCredentialVariable,
        private array $environment = [],
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[Option(description: 'Environment variable to report on; defaults to the one your configuration reads')]
        ?string $envVar = null,
    ): int {
        if (ApplicationHomeRefusal::reported($symfonyStyle, $this->configuredCredentialVariable)) {
            return Command::FAILURE;
        }

        $placeholder = $this->configuredCredentialVariable->placeholder();
        $variableName = $envVar ?? $placeholder?->variableName;
        if (null === $variableName) {
            $symfonyStyle->error('No API-key variable is configured yet. Run "init" to create a configuration, or name one explicitly with --env-var.');

            return Command::INVALID;
        }

        if (EnvironmentVariableRefusal::reported($symfonyStyle, $variableName)) {
            return Command::INVALID;
        }

        $exported = $this->environment[$variableName] ?? '';
        if ('' === $exported) {
            return $this->reportStoredOrMissing($symfonyStyle, $variableName, $this->credentialStore->read($variableName));
        }

        $shadowsStoredCredential = $this->holdsStoredCredential($symfonyStyle, $variableName);

        return $placeholder?->variableName === $variableName && $placeholder->readsFile
            ? $this->reportFromFile($symfonyStyle, $variableName, $exported, $shadowsStoredCredential)
            : $this->reportResolved($symfonyStyle, $variableName, $exported, self::ENVIRONMENT_SOURCE, $shadowsStoredCredential);
    }

    /**
     * The exported variable wins, so a store that cannot be read changes
     * nothing about the key an audit would use — it is worth a warning, not a
     * failure.
     */
    private function holdsStoredCredential(SymfonyStyle $symfonyStyle, string $variableName): bool
    {
        try {
            return null !== $this->credentialStore->read($variableName);
        } catch (UnreadableCredentialStoreException $unreadableCredentialStoreException) {
            $symfonyStyle->warning($unreadableCredentialStoreException->getMessage());

            return false;
        }
    }

    /**
     * A configuration reading the key through `%env(file:VAR)%` exports the
     * file's path, not the key, so the key an audit would use is the file's
     * content — and a file that cannot be read means no key resolves at all.
     */
    private function reportFromFile(SymfonyStyle $symfonyStyle, string $variableName, string $path, bool $shadowsStoredCredential): int
    {
        try {
            $credential = trim($this->filesystem->readFile($path));
        } catch (IOException) {
            $symfonyStyle->error(UnreadableCredentialFileException::forVariable($variableName, $path)->getMessage());

            return Command::FAILURE;
        }

        if ('' === $credential) {
            $symfonyStyle->error(UnreadableCredentialFileException::forBlankFile($variableName, $path)->getMessage());

            return Command::FAILURE;
        }

        return $this->reportResolved($symfonyStyle, $variableName, $credential, \sprintf('the file %s names', $variableName), $shadowsStoredCredential);
    }

    private function reportStoredOrMissing(SymfonyStyle $symfonyStyle, string $variableName, ?string $stored): int
    {
        return null !== $stored
            ? $this->reportResolved($symfonyStyle, $variableName, $stored, self::STORE_SOURCE, false)
            : $this->reportMissing($symfonyStyle, $variableName);
    }

    private function reportResolved(SymfonyStyle $symfonyStyle, string $variableName, string $credential, string $source, bool $shadowsStoredCredential): int
    {
        $credentialIdentity = CredentialIdentity::of($credential);

        $symfonyStyle->definitionList(
            ['Variable' => $variableName],
            ['Source' => $source],
            ['Key' => $credentialIdentity->maskedPreview],
            ['Fingerprint' => $credentialIdentity->fingerprint],
            ['Credential file' => $this->credentialStore->location() ?? 'nowhere — no per-user configuration directory could be resolved'],
        );

        if ($shadowsStoredCredential) {
            $symfonyStyle->note(\sprintf('A key is also stored on this machine, but the exported %s wins. Unset it to go back to the stored one.', $variableName));
        }

        return Command::SUCCESS;
    }

    private function reportMissing(SymfonyStyle $symfonyStyle, string $variableName): int
    {
        $symfonyStyle->warning(\sprintf('No API key resolves for %s: it is not exported, and nothing is stored for it.', $variableName));
        $symfonyStyle->text('Pick whichever fits how you work:');
        $symfonyStyle->definitionList(
            ['auth:set' => 'store the key on this machine, in a file only you can read'],
            [\sprintf('export %s=…', $variableName) => 'this shell only'],
            [\sprintf('%s=$(pass show …) audit .', $variableName) => 'straight from a password manager, nothing written to disk'],
        );

        return Command::FAILURE;
    }
}
