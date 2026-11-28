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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccountProbeInterface;

/** @internal not part of the BC promise: the command *name* (`auth:status`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
final readonly class AuthStatusCommand
{
    public const string NAME = 'auth:status';

    public const string DESCRIPTION = 'Show which API key an audit would use, without printing it';

    private const string ENVIRONMENT_SOURCE = 'the environment';

    private const string STORE_SOURCE = 'stored on this machine';

    /**
     * @param array<string, string> $environment
     * @param ?string               $federatedSignInRefusal why an audit cannot sign in through workload identity federation here
     */
    public function __construct(
        private CredentialStoreInterface $credentialStore,
        private ConfiguredCredentialVariable $configuredCredentialVariable,
        private array $environment = [],
        private Filesystem $filesystem = new Filesystem(),
        private ?CliAgentAccountProbeInterface $cliAgentAccountProbe = null,
        private ?string $federatedSignInRefusal = null,
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

        $providerSetup = (new ProviderSetupReader($this->configuredCredentialVariable, $this->cliAgentAccountProbe))->report($symfonyStyle);
        $federatedOutcome = $this->reportFederatedCredential($symfonyStyle, $providerSetup, $envVar);
        if (null !== $federatedOutcome) {
            return $federatedOutcome;
        }

        $placeholder = $this->configuredCredentialVariable->placeholder();
        $variableName = $envVar ?? $placeholder?->variableName;
        if (null === $variableName) {
            return $this->reportWithoutVariable($symfonyStyle, $providerSetup);
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
     * Reports the federated credential an audit signs in with, or why it
     * cannot. Returns the exit code, null when no federated credential
     * applies or a variable is named on the command line.
     */
    private function reportFederatedCredential(SymfonyStyle $symfonyStyle, ?ProviderSetup $providerSetup, ?string $envVar): ?int
    {
        $federatedCredential = null === $envVar ? $providerSetup?->federatedCredential() : null;
        if (null === $federatedCredential) {
            return null;
        }

        if (null !== $this->federatedSignInRefusal) {
            $symfonyStyle->error($this->federatedSignInRefusal);

            return Command::FAILURE;
        }

        $symfonyStyle->success(\sprintf('An audit uses no API key: it signs in through %s.', $federatedCredential));

        return Command::SUCCESS;
    }

    private function reportWithoutVariable(SymfonyStyle $symfonyStyle, ?ProviderSetup $providerSetup): int
    {
        if ($this->configuredCredentialVariable->platformNeedsNoApiKey()) {
            $symfonyStyle->success(true === $providerSetup?->runsOnACli()
                ? 'The auditor stores no API key for this provider: its CLI bills the account under Billing.'
                : 'The configured platform needs no API key, so an audit uses none.');

            return Command::SUCCESS;
        }

        $symfonyStyle->error('No API-key variable is configured yet. Run "init" to create a configuration, or name one explicitly with --env-var.');

        return Command::INVALID;
    }

    /**
     * Warns about a store that cannot be read and returns false: the exported
     * variable wins over it anyway.
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
     * Reports the key held by the file a `%env(file:VAR)%` variable names. A
     * file that cannot be read or is blank resolves no key.
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

        $symfonyStyle->text(\sprintf('Run "%s" to check that this key works. It sends one short test request, which a paid API bills, usually well under a cent.', AuthTestCommand::NAME));

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
