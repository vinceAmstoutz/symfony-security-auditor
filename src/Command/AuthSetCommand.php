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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;

use function Symfony\Component\String\b;

/** @internal not part of the BC promise — the command *name* (`auth:set`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
final readonly class AuthSetCommand
{
    public const string NAME = 'auth:set';

    public const string DESCRIPTION = 'Store the provider API key on this machine, in a file only you can read';

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
        #[Option(description: 'Environment variable to store the key under; defaults to the one your configuration reads')]
        ?string $envVar = null,
    ): int {
        $variableName = $envVar ?? $this->configuredCredentialVariable->name();
        if (null === $variableName) {
            $symfonyStyle->error('No API-key variable is configured yet. Run "init" first, or name one explicitly with --env-var.');

            return Command::INVALID;
        }

        $credential = $this->askForCredential($symfonyStyle, $variableName);
        if (null === $credential) {
            $symfonyStyle->error(\sprintf('Nothing to store. Re-run this command on a terminal that can prompt, or export %s instead.', $variableName));

            return Command::INVALID;
        }

        $this->credentialStore->write($variableName, $credential);

        $location = $this->credentialStore->location();
        \assert(null !== $location, 'A store that accepted a credential knows where it put it');

        $symfonyStyle->success($this->storedMessage($variableName, $location, CredentialIdentity::of($credential)));

        return Command::SUCCESS;
    }

    /**
     * A pasted key routinely carries the newline or the stray space that came
     * with it, and the provider rejects those without saying why.
     */
    private function askForCredential(SymfonyStyle $symfonyStyle, string $variableName): ?string
    {
        $answer = $symfonyStyle->askHidden(\sprintf('Paste the API key for %s (input stays hidden)', $variableName));
        $credential = b(\is_string($answer) ? $answer : '')->trim()->toString();

        return '' !== $credential ? $credential : null;
    }

    private function storedMessage(string $variableName, string $location, CredentialIdentity $credentialIdentity): string
    {
        return \sprintf(
            'Stored %1$s (%2$s, %3$s) in %4$s. Audits pick it up on their own from now on — an exported %1$s still takes precedence when you want to override it for one run.',
            $variableName,
            $credentialIdentity->maskedPreview,
            $credentialIdentity->fingerprint,
            $location,
        );
    }
}
