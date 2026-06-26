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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

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
        $containerBuilder = $this->standaloneContainerFactory->create(
            $this->standaloneConfigLoader->load(),
            $this->xdgConfigPathResolver->cacheDir(),
        );

        $application = new Application(self::APPLICATION_NAME);
        $application->addCommand($this->standaloneConsoleCommandFactory->create($containerBuilder));

        return $application;
    }
}
