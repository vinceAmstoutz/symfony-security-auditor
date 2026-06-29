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
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeInstallerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
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

    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandaloneConfigFactoryInterface $standaloneConfigFactory,
        private StandaloneConfigWriterInterface $standaloneConfigWriter,
        private BridgeInstallerInterface $bridgeInstaller,
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    /**
     * @throws UnresolvableConfigPathException
     * @throws BridgeInstallationFailedException
     */
    public function __invoke(SymfonyStyle $symfonyStyle): int
    {
        $configFile = $this->xdgConfigPathResolver->configFile();

        if ($this->isOverwriteDeclined($symfonyStyle, $configFile)) {
            $symfonyStyle->warning('Aborted; the existing configuration was left untouched.');

            return Command::SUCCESS;
        }

        $provider = $this->ask($symfonyStyle, 'Which AI provider do you want to use? (any symfony/ai platform — e.g. anthropic, openai, gemini, ollama)', 'anthropic');
        $model = $this->ask($symfonyStyle, 'Which model should the auditor use?', 'claude-opus-4-8');
        $environmentVariable = $this->ask($symfonyStyle, 'Which environment variable holds the API key?', \sprintf('%s_API_KEY', u($provider)->upper()));

        $this->standaloneConfigWriter->write($configFile, $this->standaloneConfigFactory->create($provider, $model, $environmentVariable));
        $this->bridgeInstaller->install($provider, $this->xdgConfigPathResolver->dataDir());

        $symfonyStyle->success(\sprintf('Configuration written to %s. Export %s, then run "audit <path>".', $configFile, $environmentVariable));

        return Command::SUCCESS;
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
}
