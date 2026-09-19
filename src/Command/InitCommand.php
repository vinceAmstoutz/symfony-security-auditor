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
use Symfony\Component\Console\Exception\MissingInputException;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKeyNormalizer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BaseUrlPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialStoreInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EndpointPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\OptionalApiKeyPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigWriterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

use function Symfony\Component\String\b;
use function Symfony\Component\String\u;

/** @internal not part of the BC promise — the command *name* (`init`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION, help: InitCommandHelp::HELP)]
final readonly class InitCommand
{
    public const string NAME = 'init';

    public const string DESCRIPTION = 'Create the standalone configuration and download the selected provider bridge';

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

        if ($this->isOverwriteDeclined($symfonyStyle, $configFile, $initCommandInput->force)) {
            $symfonyStyle->warning('Aborted; the existing configuration was left untouched (use --force to overwrite).');

            return Command::SUCCESS;
        }

        $provider = b($initCommandInput->provider ?? $this->ask($symfonyStyle, 'Which AI provider do you want to use? (any symfony/ai platform — e.g. anthropic, openai, gemini, mistral, ollama, or generic.my_gateway for an AI gateway)', 'anthropic'))->trim()->toString();

        if ($this->refused($symfonyStyle, InitRefusal::forProviderText($provider))) {
            return Command::INVALID;
        }

        $provider = $this->providerKeyNormalizer->normalize($provider);
        $providerKey = ProviderKey::of($provider);

        if ($this->refused($symfonyStyle, InitRefusal::forProvider($providerKey, $provider, $initCommandInput, $configFile))) {
            return Command::INVALID;
        }

        $model = b($initCommandInput->model ?? $this->ask($symfonyStyle, 'Which model should the auditor use?', 'claude-opus-4-8'))->trim()->toString();

        if ($this->refused($symfonyStyle, InitRefusal::forModel($model))) {
            return Command::INVALID;
        }

        $envVar = $this->resolveApiKeyVariable($symfonyStyle, $initCommandInput, $providerKey);

        if ($this->refused($symfonyStyle, InitRefusal::forEnvironmentVariable($envVar))) {
            return Command::INVALID;
        }

        $baseUrl = $this->resolveBaseUrl($symfonyStyle, $initCommandInput, $providerKey);

        if ($this->refused($symfonyStyle, InitRefusal::forResolvedBaseUrl($providerKey, $provider, $baseUrl))) {
            return Command::INVALID;
        }

        $endpoint = $this->resolveEndpoint($symfonyStyle, $initCommandInput, $providerKey);

        if ($this->refused($symfonyStyle, InitRefusal::forResolvedEndpoint($providerKey, $provider, $endpoint))) {
            return Command::INVALID;
        }

        $symfonyStyle->text(\sprintf('Downloading the %s provider bridge with composer — this can take a minute…', OutputFormatter::escape($providerKey->platform)));
        $this->bridgeInstaller->install($provider, $this->xdgConfigPathResolver->dataDir());
        $this->standaloneConfigWriter->write($configFile, $this->standaloneConfigFactory->create($provider, $model, $envVar, $baseUrl, $endpoint));

        $this->reportWritten($symfonyStyle, $configFile, $provider, $model, $envVar);

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

    private function refused(SymfonyStyle $symfonyStyle, ?string $violation): bool
    {
        if (null === $violation) {
            return false;
        }

        $symfonyStyle->error($violation);

        return true;
    }

    private function reportWritten(SymfonyStyle $symfonyStyle, string $configFile, string $provider, string $model, ?string $envVar): void
    {
        $symfonyStyle->success(\sprintf('Configuration written to %s.', $configFile));
        $symfonyStyle->definitionList(
            ['Provider' => OutputFormatter::escape($provider)],
            ['Model' => OutputFormatter::escape($model)],
            ['API key variable' => $envVar ?? 'none — this platform is configured without a credential'],
        );

        if (null !== $envVar) {
            $this->offerToStoreCredential($symfonyStyle, $envVar);
        }
    }

    private function isOverwriteDeclined(SymfonyStyle $symfonyStyle, string $configFile, bool $force): bool
    {
        return !$force
            && $this->filesystem->exists($configFile)
            && !$symfonyStyle->confirm(\sprintf('A configuration already exists at %s. Overwrite it?', $configFile), false);
    }

    private function ask(SymfonyStyle $symfonyStyle, string $question, string $default): string
    {
        $answer = $symfonyStyle->ask($question, $default);
        \assert(\is_string($answer));

        return $answer;
    }

    /**
     * A platform that makes you supply its endpoint is one you host yourself,
     * so no credential is invented for it: naming a variable nobody set is what
     * made `init --provider=ollama` end in "No API key available".
     */
    private function defaultApiKeyVariable(ProviderKey $providerKey): ?string
    {
        return EndpointPlatforms::requires($providerKey)
            ? null
            : \sprintf('%s_API_KEY', u($providerKey->platform)->upper()->replaceMatches('/[^A-Z0-9]+/', ''));
    }

    /**
     * Null means the connection is written without an `api_key`. Only the
     * platforms whose key the bundle leaves optional may reach that, so an
     * empty answer elsewhere still falls through to the refusal.
     */
    private function resolveApiKeyVariable(SymfonyStyle $symfonyStyle, InitCommandInput $initCommandInput, ProviderKey $providerKey): ?string
    {
        if ($initCommandInput->noApiKey) {
            return null;
        }

        $default = $this->defaultApiKeyVariable($providerKey);
        $answer = $initCommandInput->envVar ?? (null === $default
            ? $this->askRequired($symfonyStyle, \sprintf('Which environment variable holds the API key for %s? Leave it empty to write none, which is what a local install needs', $providerKey->platform))
            : $this->ask($symfonyStyle, 'Which environment variable holds the API key?', $default));

        $envVar = b($answer)->trim()->toString();

        return '' === $envVar && OptionalApiKeyPlatforms::accept($providerKey) ? null : $envVar;
    }

    private function resolveEndpoint(SymfonyStyle $symfonyStyle, InitCommandInput $initCommandInput, ProviderKey $providerKey): ?string
    {
        if (!EndpointPlatforms::accept($providerKey)) {
            return null;
        }

        $endpoint = b($initCommandInput->endpoint ?? $this->askRequired($symfonyStyle, \sprintf('Endpoint %s should reach (e.g. http://localhost:11434)%s', $providerKey->platform, EndpointPlatforms::requires($providerKey) ? '' : ', or leave it empty to keep the default')))->trim()->toString();

        return '' !== $endpoint ? $endpoint : null;
    }

    /**
     * Asked without a default, so no misleading `[]` is offered for a value that
     * is required. `QuestionHelper` rethrows at end of input when the default is
     * null, which would abort with exit 1 instead of the refusal this returns to.
     */
    private function askRequired(SymfonyStyle $symfonyStyle, string $question): string
    {
        try {
            $answer = $symfonyStyle->ask($question);
        } catch (MissingInputException) {
            return '';
        }

        return \is_string($answer) ? $answer : '';
    }

    private function resolveBaseUrl(SymfonyStyle $symfonyStyle, InitCommandInput $initCommandInput, ProviderKey $providerKey): ?string
    {
        if (!BaseUrlPlatforms::accept($providerKey)) {
            return null;
        }

        $baseUrl = b($initCommandInput->baseUrl ?? $this->askRequired($symfonyStyle, \sprintf('Base URL of the endpoint you want %s to reach (required, e.g. https://your-gateway.example)', $providerKey->platform)))->trim()->toString();

        return '' !== $baseUrl ? $baseUrl : null;
    }
}
