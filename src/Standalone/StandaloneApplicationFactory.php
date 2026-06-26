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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Command\LazyCommand;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneApplicationFactory
{
    private const string APPLICATION_NAME = 'symfony-security-auditor';

    public function __construct(
        private StandaloneConfigLoader $standaloneConfigLoader,
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandaloneContainerFactory $standaloneContainerFactory = new StandaloneContainerFactory(),
        private StandaloneConsoleCommandFactory $standaloneConsoleCommandFactory = new StandaloneConsoleCommandFactory(),
    ) {}

    /**
     * @param array<string, string> $environment
     */
    public static function fromEnvironment(array $environment): self
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(
            $environment['XDG_CONFIG_HOME'] ?? null,
            $environment['XDG_CACHE_HOME'] ?? null,
            $environment['HOME'] ?? null,
        );

        return new self(
            new StandaloneConfigLoader($xdgConfigPathResolver, new StandalonePlatformConfigResolver($environment)),
            $xdgConfigPathResolver,
        );
    }

    public function create(): Application
    {
        $application = new Application(self::APPLICATION_NAME);
        $application->addCommand($this->lazyAuditCommand());

        return $application;
    }

    private function lazyAuditCommand(): LazyCommand
    {
        return new LazyCommand(
            AuditCommand::NAME,
            [StandaloneConsoleCommandFactory::AUDIT_ALIAS],
            AuditCommand::DESCRIPTION,
            false,
            fn (): Command => $this->standaloneConsoleCommandFactory->create($this->buildContainer()),
        );
    }

    private function buildContainer(): ContainerBuilder
    {
        return $this->standaloneContainerFactory->create(
            $this->standaloneConfigLoader->load(),
            $this->xdgConfigPathResolver->cacheDir(),
        );
    }
}
