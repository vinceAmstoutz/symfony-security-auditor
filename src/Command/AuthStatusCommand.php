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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialStoreInterface;
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
    ) {}

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[Option(description: 'Environment variable to report on; defaults to the one your configuration reads')]
        ?string $envVar = null,
    ): int {
        $variableName = $envVar ?? $this->configuredCredentialVariable->name();
        if (null === $variableName) {
            $symfonyStyle->error('No API-key variable is configured yet. Run "init" to create a configuration, or name one explicitly with --env-var.');

            return Command::INVALID;
        }

        $exported = $this->environment[$variableName] ?? '';
        $stored = $this->credentialStore->read($variableName);

        return '' !== $exported
            ? $this->reportResolved($symfonyStyle, $variableName, $exported, self::ENVIRONMENT_SOURCE, null !== $stored)
            : $this->reportStoredOrMissing($symfonyStyle, $variableName, $stored);
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
