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
use Symfony\Component\Console\Attribute\MapInput;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKeyNormalizer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BaseUrlPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfigKeyInstanceName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialStoreInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HandWrittenPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\InstanceKeyedPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigWriterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

use function Symfony\Component\String\b;
use function Symfony\Component\String\u;

/** @internal not part of the BC promise — the command *name* (`init`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
final readonly class InitCommand
{
    public const string NAME = 'init';

    public const string DESCRIPTION = 'Create the standalone configuration and download the selected provider bridge';

    private const string ENV_VAR_NAME_PATTERN = '/^[A-Za-z_]\w*$/';

    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandaloneConfigFactoryInterface $standaloneConfigFactory,
        private StandaloneConfigWriterInterface $standaloneConfigWriter,
        private BridgeInstallerInterface $bridgeInstaller,
        private CredentialStoreInterface $credentialStore,
        private Filesystem $filesystem = new Filesystem(),
        private ProviderKeyNormalizer $providerKeyNormalizer = new ProviderKeyNormalizer(),
    ) {}

    /**
     * @throws UnresolvableConfigPathException
     * @throws BridgeInstallationFailedException
     */
    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[MapInput] InitCommandInput $initCommandInput,
    ): int {
        $configFile = $this->xdgConfigPathResolver->configFile();

        if (!$initCommandInput->force && $this->isOverwriteDeclined($symfonyStyle, $configFile)) {
            $symfonyStyle->warning('Aborted; the existing configuration was left untouched (use --force to overwrite).');

            return Command::SUCCESS;
        }

        $provider = b($initCommandInput->provider ?? $this->ask($symfonyStyle, 'Which AI provider do you want to use? (any symfony/ai platform — e.g. anthropic, openai, gemini, mistral, ollama, or generic.my_gateway for an AI gateway)', 'anthropic'))->trim()->toString();
        $model = b($initCommandInput->model ?? $this->ask($symfonyStyle, 'Which model should the auditor use?', 'claude-opus-4-8'))->trim()->toString();

        $violation = $this->identityViolation($provider, $model);
        if (null !== $violation) {
            $symfonyStyle->error($violation);

            return Command::INVALID;
        }

        $provider = $this->providerKeyNormalizer->normalize($provider);
        $providerKey = ProviderKey::of($provider);

        $violation = $this->platformViolation($providerKey, $provider, $initCommandInput->baseUrl, $configFile);
        if (null !== $violation) {
            $symfonyStyle->error($violation);

            return Command::INVALID;
        }

        $envVar = b($initCommandInput->envVar ?? $this->ask($symfonyStyle, 'Which environment variable holds the API key?', $this->defaultApiKeyVariable($providerKey)))->trim()->toString();

        if (1 !== preg_match(self::ENV_VAR_NAME_PATTERN, $envVar)) {
            $symfonyStyle->error(\sprintf('"%s" is not a valid environment variable name (letters, digits, and underscores only; must not start with a digit).', $envVar));

            return Command::INVALID;
        }

        $baseUrl = $this->resolveBaseUrl($symfonyStyle, $initCommandInput, $providerKey);

        if (null === $baseUrl && BaseUrlPlatforms::accept($providerKey)) {
            $symfonyStyle->error(\sprintf('"%s" requires a base URL, so nothing was written. Re-run with --base-url=<origin>.', $provider));

            return Command::INVALID;
        }

        $this->bridgeInstaller->install($provider, $this->xdgConfigPathResolver->dataDir());
        $this->standaloneConfigWriter->write($configFile, $this->standaloneConfigFactory->create($provider, $model, $envVar, $baseUrl));

        $symfonyStyle->success(\sprintf('Configuration written to %s.', $configFile));
        $this->offerToStoreCredential($symfonyStyle, $envVar);

        return Command::SUCCESS;
    }

    /**
     * Asking here is what makes a guided install end with a working setup:
     * the configuration alone only names a variable, and a user who has to go
     * and export it separately is a user whose first audit fails.
     */
    private function offerToStoreCredential(SymfonyStyle $symfonyStyle, string $envVar): void
    {
        $answer = $symfonyStyle->askHidden(\sprintf('Paste the API key for %s to store it on this machine, or press Enter to skip (input stays hidden)', $envVar));
        $credential = b(\is_string($answer) ? $answer : '')->trim()->toString();

        if ('' === $credential) {
            $symfonyStyle->note(\sprintf('No key stored. Export %1$s before auditing, or run "auth:set" at any time to store it. Keeping the key out of your shell history: docs/configuration.md#providing-the-api-key', $envVar));

            return;
        }

        $this->storeCredential($symfonyStyle, $envVar, $credential);
    }

    private function storeCredential(SymfonyStyle $symfonyStyle, string $envVar, string $credential): void
    {
        try {
            $this->credentialStore->write($envVar, $credential);
        } catch (CredentialStoreWriteException|UnreadableCredentialStoreException $credentialStoreFailure) {
            $symfonyStyle->warning(\sprintf('The configuration is ready, but the key could not be stored: %s Export %s before auditing instead.', $credentialStoreFailure->getMessage(), $envVar));

            return;
        }

        $symfonyStyle->success(\sprintf('Stored %s (%s). You can run "audit <path>" now — no environment variable needed.', $envVar, CredentialIdentity::of($credential)->maskedPreview));
    }

    /**
     * Checked on the raw bytes, before `ProviderKeyNormalizer` — its `u()`
     * call throws on non-UTF-8 input, which must reject with exit code 2
     * instead of crashing.
     */
    private function identityViolation(string $provider, string $model): ?string
    {
        return match (true) {
            1 !== preg_match('//u', $provider) => 'The provider must be valid UTF-8 text.',
            '' === $provider => 'The provider must not be empty.',
            1 !== preg_match('//u', $model) => 'The model must be valid UTF-8 text.',
            '' === $model => 'The model must not be empty.',
            default => null,
        };
    }

    private function isOverwriteDeclined(SymfonyStyle $symfonyStyle, string $configFile): bool
    {
        return $this->filesystem->exists($configFile)
            && !$symfonyStyle->confirm(\sprintf('A configuration already exists at %s. Overwrite it?', $configFile), false);
    }

    private function ask(SymfonyStyle $symfonyStyle, string $question, string $default): string
    {
        $answer = $symfonyStyle->ask($question, $default);
        \assert(\is_string($answer));

        return $answer;
    }

    private function defaultApiKeyVariable(ProviderKey $providerKey): string
    {
        return \sprintf('%s_API_KEY', u($providerKey->platform)->upper()->replaceMatches('/[^A-Z0-9]+/', ''));
    }

    private function platformViolation(ProviderKey $providerKey, string $provider, ?string $baseUrl, string $configFile): ?string
    {
        if ('' === $providerKey->platform) {
            return \sprintf('"%s" names no platform before the dot. Give the platform first, for example "generic.my_gateway".', $provider);
        }

        return $this->writabilityViolation($providerKey, $provider, $baseUrl, $configFile)
            ?? $this->providerNameViolation($providerKey, $provider);
    }

    private function providerNameViolation(ProviderKey $providerKey, string $provider): ?string
    {
        if (InstanceKeyedPlatforms::needsAnInstance($providerKey)) {
            return \sprintf('"%1$s" is configured per instance, so it needs an instance name: use "%1$s.<instance>", for example "%1$s.my_gateway".', $provider);
        }

        if (InstanceKeyedPlatforms::rejectsAnInstance($providerKey)) {
            return \sprintf('"%s" takes a single connection block and names no instance, so drop the instance and use "%s".', $provider, $providerKey->platform);
        }

        if (null !== $providerKey->instance && !ConfigKeyInstanceName::isUsable($providerKey->instance)) {
            return \sprintf('"%s" uses an instance name the config file cannot be read back with. Give it a name, for example "%s.my_gateway".', $provider, $providerKey->platform);
        }

        return null;
    }

    private function writabilityViolation(ProviderKey $providerKey, string $provider, ?string $baseUrl, string $configFile): ?string
    {
        $handWritten = HandWrittenPlatforms::requirementOf($providerKey);
        if (null !== $handWritten) {
            return \sprintf('"%s" needs %s, which "init" does not write. Configure it by hand in %s.', $provider, $handWritten, $configFile);
        }

        if (null !== $baseUrl && !BaseUrlPlatforms::accept($providerKey)) {
            return \sprintf('--base-url applies to the platforms that expose one (%s); "%s" has no base_url key.', implode(', ', BaseUrlPlatforms::writableNames()), $provider);
        }

        return null;
    }

    private function resolveBaseUrl(SymfonyStyle $symfonyStyle, InitCommandInput $initCommandInput, ProviderKey $providerKey): ?string
    {
        if (!BaseUrlPlatforms::accept($providerKey)) {
            return null;
        }

        $baseUrl = b($initCommandInput->baseUrl ?? $this->ask($symfonyStyle, 'Which base URL does this platform expose? (required by this platform)', ''))->trim()->toString();

        return '' !== $baseUrl ? $baseUrl : null;
    }
}
