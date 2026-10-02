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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialStoreInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;

/** @internal not part of the BC promise — the command *name* (`auth:remove`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
final readonly class AuthRemoveCommand
{
    public const string NAME = 'auth:remove';

    public const string DESCRIPTION = 'Forget the API key stored on this machine';

    public function __construct(
        private CredentialStoreInterface $credentialStore,
        private ConfiguredCredentialVariable $configuredCredentialVariable,
    ) {}

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[Option(description: 'Environment variable whose stored key to forget; defaults to the one your configuration reads')]
        ?string $envVar = null,
    ): int {
        $variableName = $envVar ?? $this->configuredCredentialVariable->name();
        if (null === $variableName) {
            $symfonyStyle->error('No API-key variable is configured yet, so there is nothing to forget. Name one explicitly with --env-var if you stored it under a different name.');

            return Command::INVALID;
        }

        if (!$this->credentialStore->remove($variableName)) {
            $symfonyStyle->warning(\sprintf('Nothing was stored for %s, so nothing changed.', $variableName));

            return Command::SUCCESS;
        }

        $symfonyStyle->success(\sprintf('Forgot the stored key for %1$s. Audits need %1$s in the environment again — the key itself is still valid with your provider, so revoke it there too if that was the point.', $variableName));

        return Command::SUCCESS;
    }
}
