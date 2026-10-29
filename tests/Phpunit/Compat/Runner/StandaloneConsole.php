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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner;

use Override;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BundledAiPlatformVersion;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplicationFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Step;

/**
 * The standalone binary, built by its own factory from the environment the
 * way `bin/symfony-security-auditor` builds it, in the step's working
 * directory and with the workspace's XDG directories as its home. Its bridge
 * installer runs the workspace's offline stand-in for Composer.
 */
final readonly class StandaloneConsole implements ConsoleInterface
{
    public function __construct(
        private Workspace $workspace,
    ) {}

    #[Override]
    public function run(Step $step): ConsoleRun
    {
        $workingDirectory = ConsoleTester::enter($step, $this->workspace);
        ProcessEnvironment::set('PWD', $workingDirectory);

        $standaloneApplication = StandaloneApplicationFactory::fromEnvironment(ProcessEnvironment::current(), null, $this->bridgeInstaller())->create();

        return ConsoleTester::run($standaloneApplication, $step, $this->workspace);
    }

    private function bridgeInstaller(): ComposerBridgeInstaller
    {
        $composer = $this->workspace->resolve('bin/composer');

        return new ComposerBridgeInstaller(
            static fn (string $package, ?string $aiPlatformPin, string $targetDirectory, string ...$morePackages): Process => new Process([$composer, 'require', $package, ...array_values($morePackages)]),
            aiPlatformPin: BundledAiPlatformVersion::detect(),
        );
    }

    /**
     * @return array<string, string>
     */
    public static function homeEnvironment(): array
    {
        return [
            'XDG_CONFIG_HOME' => '{workspace}/home/config',
            'XDG_CACHE_HOME' => '{workspace}/home/cache',
            'XDG_DATA_HOME' => '{workspace}/home/data',
        ];
    }
}
