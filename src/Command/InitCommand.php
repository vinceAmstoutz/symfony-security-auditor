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
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKeyNormalizer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BaseUrlPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BedrockMantleRoute;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CliAgentPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialStoreInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EndpointPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HandWrittenPlatformBlock;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\OptionalApiKeyPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PlatformConnection;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\RoundTripYaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigWriterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelListInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PricedModelListInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\HiddenInputUnavailableException;

use function Symfony\Component\String\b;
use function Symfony\Component\String\u;

/** @internal not part of the BC promise: the command *name* (`init`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION, help: InitCommandHelp::HELP)]
final readonly class InitCommand
{
    public const string NAME = 'init';

    public const string DESCRIPTION = 'Create the standalone configuration and download the selected provider bridge';

    private const string MODEL_PLACEHOLDER = '<model id>';

    private const string LOCAL_OLLAMA = 'http://localhost:11434';

    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandaloneConfigFactoryInterface $standaloneConfigFactory,
        private StandaloneConfigWriterInterface $standaloneConfigWriter,
        private BridgeInstallerInterface $bridgeInstaller,
        private CredentialStoreInterface $credentialStore,
        private Filesystem $filesystem = new Filesystem(),
        private ProviderKeyNormalizer $providerKeyNormalizer = new ProviderKeyNormalizer(),
        private CredentialPromptInterface $credentialPrompt = new HiddenCredentialPrompt(),
        private ?PricedModelListInterface $pricedModelList = null,
        private ?ConnectionTestRunnerInterface $connectionTestRunner = null,
        private ?PulledModelListInterface $pulledModelList = null,
    ) {}

    /**
     * @throws UnresolvableConfigPathException
     * @throws BridgeInstallationFailedException
     */
    public function __invoke(
        SymfonyStyle $symfonyStyle,
        InputInterface $input,
        #[MapInput] InitCommandInput $initCommandInput,
    ): int {
        return $this->configure($symfonyStyle, $initCommandInput, $input->isInteractive());
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws BridgeInstallationFailedException
     */
    private function configure(SymfonyStyle $symfonyStyle, InitCommandInput $initCommandInput, bool $interactive): int
    {
        $configFile = $this->xdgConfigPathResolver->configFile();

        $provider = b($initCommandInput->provider ?? InitProviderQuestion::ask($symfonyStyle))->trim()->toString();

        if ($this->refused($symfonyStyle, InitRefusal::forProviderText($provider))) {
            return Command::INVALID;
        }

        $provider = $this->providerKeyNormalizer->normalize($provider);
        $providerKey = ProviderKey::of($provider);

        if ($this->refusedProvider($symfonyStyle, $provider, $providerKey, $initCommandInput, $configFile)) {
            return Command::INVALID;
        }

        $platformConnection = $this->resolveConnection($symfonyStyle, $initCommandInput, $providerKey, $provider, $interactive);

        if (!$platformConnection instanceof PlatformConnection) {
            return Command::INVALID;
        }

        $model = b($initCommandInput->model ?? (new InitModelQuestion($this->pricedModelList, $this->pulledModelList))->ask($symfonyStyle, $providerKey, $platformConnection->endpoint))->trim()->toString();

        if ($this->refused($symfonyStyle, InitRefusal::forModel($model, $providerKey))) {
            return Command::INVALID;
        }

        $envVar = $this->resolveApiKeyVariable($initCommandInput, $providerKey);

        if ($this->refused($symfonyStyle, InitRefusal::forEnvironmentVariable($envVar))) {
            return Command::INVALID;
        }

        if ($this->isOverwriteDeclined($symfonyStyle, $configFile, $initCommandInput->force)) {
            $symfonyStyle->warning('Aborted; the existing configuration was left untouched (use --force to overwrite).');

            return Command::SUCCESS;
        }

        $this->installBridges($symfonyStyle, $provider, $providerKey, $model);
        $this->standaloneConfigWriter->write($configFile, $this->standaloneConfigFactory->create($provider, $model, $envVar, $platformConnection));

        $this->reportWritten($symfonyStyle, $configFile, $provider, $model, $envVar);
        ConnectionTestOffer::make($this->connectionTestRunner, $symfonyStyle, $interactive);

        return Command::SUCCESS;
    }

    /**
     * Asking here is what makes a guided install end with a working setup:
     * the configuration alone only names a variable and a user who has to go
     * and export it separately is a user whose first audit fails.
     */
    private function offerToStoreCredential(SymfonyStyle $symfonyStyle, string $envVar): void
    {
        try {
            $credential = $this->credentialPrompt->ask($symfonyStyle, \sprintf('Paste the API key for %s to store it on this machine, or press Enter to skip (input stays hidden)', $envVar));
        } catch (HiddenInputUnavailableException) {
            $symfonyStyle->note(\sprintf('This terminal cannot hide what you type, so no key was asked for. Run "auth:set" on one that can, or export %s before auditing.', $envVar));

            return;
        }

        if (null === $credential) {
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
     * A platform whose block `init` cannot write still gets its bridge and
     * the block to complete; either way the provider is not taken further.
     * What that path is given is checked before the bridge is installed, the
     * way the written path checks it, so a refused instance name never reaches
     * the printed block and a key pasted into `--env-var` never reaches the
     * command line echoed under an install failure.
     *
     * @throws UnresolvableConfigPathException
     * @throws BridgeInstallationFailedException
     */
    private function refusedProvider(SymfonyStyle $symfonyStyle, string $provider, ProviderKey $providerKey, InitCommandInput $initCommandInput, string $configFile): bool
    {
        $handWritten = InitRefusal::forHandWrittenPlatform($providerKey, $provider, $configFile);

        if (null === $handWritten) {
            return $this->refused($symfonyStyle, InitRefusal::forProvider($providerKey, $provider, $initCommandInput));
        }

        $model = null === $initCommandInput->model ? self::MODEL_PLACEHOLDER : b($initCommandInput->model)->trim()->toString();
        $envVar = null === $initCommandInput->envVar ? null : b($initCommandInput->envVar)->trim()->toString();

        if ($this->refused($symfonyStyle, InitRefusal::forNamedInstance($providerKey, $provider) ?? InitRefusal::forModelText($model) ?? InitRefusal::forEnvironmentVariable($envVar))) {
            return true;
        }

        $this->installBridge($symfonyStyle, $provider, $providerKey);
        $symfonyStyle->error($handWritten);
        $symfonyStyle->writeln(OutputFormatter::escape(RoundTripYaml::dump(HandWrittenPlatformBlock::for($providerKey, $model), \PHP_INT_MAX, 4)));

        return true;
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws BridgeInstallationFailedException
     */
    private function installBridges(SymfonyStyle $symfonyStyle, string $provider, ProviderKey $providerKey, string $model): void
    {
        $companionPlatform = BedrockMantleRoute::applies($providerKey) ? BedrockMantleRoute::companionPlatform($model) : null;

        $this->installBridge($symfonyStyle, $provider, $providerKey, ...(null !== $companionPlatform ? [$companionPlatform] : []));
    }

    /**
     * @throws UnresolvableConfigPathException
     * @throws BridgeInstallationFailedException
     */
    private function installBridge(SymfonyStyle $symfonyStyle, string $provider, ProviderKey $providerKey, string ...$companionPlatforms): void
    {
        $symfonyStyle->text(\sprintf('Installing support for %s — this can take a minute…', OutputFormatter::escape(ProviderNames::ofPlatform($providerKey->platform))));
        $this->bridgeInstaller->install($provider, $this->xdgConfigPathResolver->dataDir(), ...$companionPlatforms);
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
        if (null === $envVar) {
            $symfonyStyle->definitionList(['Provider' => OutputFormatter::escape($provider)], ['Model' => OutputFormatter::escape($model)]);

            return;
        }

        $symfonyStyle->definitionList(['Provider' => OutputFormatter::escape($provider)], ['Model' => OutputFormatter::escape($model)], ['API key variable' => $envVar]);
        $this->offerToStoreCredential($symfonyStyle, $envVar);
    }

    private function isOverwriteDeclined(SymfonyStyle $symfonyStyle, string $configFile, bool $force): bool
    {
        return !$force
            && $this->filesystem->exists($configFile)
            && !$symfonyStyle->confirm(\sprintf('A configuration already exists at %s. Overwrite it?', $configFile), false);
    }

    private function defaultApiKeyVariable(ProviderKey $providerKey): string
    {
        return \sprintf('%s_API_KEY', u($providerKey->platform)->upper()->replaceMatches('/[^A-Z0-9]+/', ''));
    }

    /**
     * Null means the connection is written without an `api_key`. Only the
     * platforms whose key the bundle leaves optional may reach that, so an
     * empty answer elsewhere still falls through to the refusal. A platform
     * that makes you supply its endpoint is one you host yourself, so no
     * credential is asked for unless `--env-var` names one.
     */
    private function resolveApiKeyVariable(InitCommandInput $initCommandInput, ProviderKey $providerKey): ?string
    {
        if ($initCommandInput->noApiKey || CliAgentPlatforms::declares($providerKey) || (null === $initCommandInput->envVar && EndpointPlatforms::requires($providerKey))) {
            return null;
        }

        $answer = $initCommandInput->envVar ?? $this->defaultApiKeyVariable($providerKey);

        $envVar = b($answer)->trim()->toString();

        return '' === $envVar && OptionalApiKeyPlatforms::accept($providerKey) ? null : $envVar;
    }

    private function resolveEndpoint(SymfonyStyle $symfonyStyle, InitCommandInput $initCommandInput, ProviderKey $providerKey, bool $interactive): ?string
    {
        if (!EndpointPlatforms::accept($providerKey)) {
            return null;
        }

        if (null === $initCommandInput->endpoint && $interactive && 'ollama' === $providerKey->platform) {
            return b(InitPrompt::withDefault($symfonyStyle, 'Where does Ollama run?', self::LOCAL_OLLAMA))->trim()->toString();
        }

        $endpoint = b($initCommandInput->endpoint ?? InitPrompt::required($symfonyStyle, \sprintf('Endpoint %s should reach (e.g. http://localhost:11434)%s', $providerKey->platform, EndpointPlatforms::requires($providerKey) ? '' : ', or leave it empty to keep the default')))->trim()->toString();

        return '' !== $endpoint ? $endpoint : null;
    }

    private function resolveConnection(SymfonyStyle $symfonyStyle, InitCommandInput $initCommandInput, ProviderKey $providerKey, string $provider, bool $interactive): ?PlatformConnection
    {
        $baseUrl = $this->resolveBaseUrl($symfonyStyle, $initCommandInput, $providerKey);
        if ($this->refused($symfonyStyle, InitRefusal::forResolvedBaseUrl($providerKey, $provider, $baseUrl))) {
            return null;
        }

        $endpoint = $this->resolveEndpoint($symfonyStyle, $initCommandInput, $providerKey, $interactive);
        if ($this->refused($symfonyStyle, InitRefusal::forResolvedEndpoint($providerKey, $provider, $endpoint))) {
            return null;
        }

        $deployment = $this->resolveDeployment($symfonyStyle, $initCommandInput, $providerKey);

        return $this->refused($symfonyStyle, DeploymentRefusal::of($providerKey, $provider, $deployment)) ? null : new PlatformConnection($baseUrl, $endpoint, $deployment);
    }

    private function resolveDeployment(SymfonyStyle $symfonyStyle, InitCommandInput $initCommandInput, ProviderKey $providerKey): ?string
    {
        if ('azure' !== $providerKey->platform) {
            return $initCommandInput->deployment;
        }

        return b($initCommandInput->deployment ?? InitPrompt::required($symfonyStyle, 'Azure OpenAI deployment name'))->trim()->toString();
    }

    private function resolveBaseUrl(SymfonyStyle $symfonyStyle, InitCommandInput $initCommandInput, ProviderKey $providerKey): ?string
    {
        if (!BaseUrlPlatforms::accept($providerKey)) {
            return null;
        }

        $baseUrl = b($initCommandInput->baseUrl ?? InitPrompt::required($symfonyStyle, \sprintf('What is the URL of %s? e.g. %s', ProviderNames::ofPlatform($providerKey->platform), 'azure' === $providerKey->platform ? 'https://<resource>.openai.azure.com' : 'https://your-gateway.example')))->trim()->toString();

        return '' !== $baseUrl ? $baseUrl : null;
    }
}
