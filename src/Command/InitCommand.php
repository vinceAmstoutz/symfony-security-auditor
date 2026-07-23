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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKeyNormalizer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigWriterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

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
        private Filesystem $filesystem = new Filesystem(),
        private ProviderKeyNormalizer $providerKeyNormalizer = new ProviderKeyNormalizer(),
    ) {}

    /**
     * @throws UnresolvableConfigPathException
     * @throws BridgeInstallationFailedException
     */
    public function __invoke(
        SymfonyStyle $symfonyStyle,
        #[Option(description: 'AI provider to configure (any symfony/ai platform — e.g. anthropic, openai, gemini); skips the prompt when set')]
        ?string $provider = null,
        #[Option(description: 'Model the auditor should use; skips the prompt when set')]
        ?string $model = null,
        #[Option(description: 'Environment variable holding the API key; defaults to <PROVIDER>_API_KEY')]
        ?string $envVar = null,
        #[Option(description: 'Overwrite an existing configuration without asking')]
        bool $force = false,
    ): int {
        $configFile = $this->xdgConfigPathResolver->configFile();

        if (!$force && $this->isOverwriteDeclined($symfonyStyle, $configFile)) {
            $symfonyStyle->warning('Aborted; the existing configuration was left untouched (use --force to overwrite).');

            return Command::SUCCESS;
        }

        $provider ??= $this->ask($symfonyStyle, 'Which AI provider do you want to use? (any symfony/ai platform — e.g. anthropic, openai, gemini, mistral, ollama)', 'anthropic');
        $provider = $this->providerKeyNormalizer->normalize($provider);
        $model = u($model ?? $this->ask($symfonyStyle, 'Which model should the auditor use?', 'claude-opus-4-8'))->trim()->toString();
        $envVar = u($envVar ?? $this->ask($symfonyStyle, 'Which environment variable holds the API key?', $this->defaultApiKeyVariable($provider)))->trim()->toString();

        $violation = $this->inputViolation($provider, $model, $envVar);
        if (null !== $violation) {
            $symfonyStyle->error($violation);

            return Command::INVALID;
        }

        $this->bridgeInstaller->install($provider, $this->xdgConfigPathResolver->dataDir());
        $this->standaloneConfigWriter->write($configFile, $this->standaloneConfigFactory->create($provider, $model, $envVar));

        $symfonyStyle->success(\sprintf('Configuration written to %s. Export %s, then run "audit <path>".', $configFile, $envVar));

        return Command::SUCCESS;
    }

    private function inputViolation(string $provider, string $model, string $envVar): ?string
    {
        if ('' === $provider) {
            return 'The provider must not be empty.';
        }

        if ('' === $model) {
            return 'The model must not be empty.';
        }

        if (1 !== preg_match(self::ENV_VAR_NAME_PATTERN, $envVar)) {
            return \sprintf('"%s" is not a valid environment variable name (letters, digits, and underscores only; must not start with a digit).', $envVar);
        }

        return null;
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

    private function defaultApiKeyVariable(string $provider): string
    {
        return \sprintf('%s_API_KEY', u($provider)->upper()->replaceMatches('/[^A-Z0-9]+/', ''));
    }
}
