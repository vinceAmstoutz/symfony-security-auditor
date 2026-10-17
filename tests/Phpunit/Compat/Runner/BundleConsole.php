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
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\HttpKernel\KernelInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Scenario;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Step;

/**
 * `bin/console` of an application with the bundle installed: each command
 * boots its own kernel, as each invocation of a terminal user does.
 */
final readonly class BundleConsole implements ConsoleInterface
{
    private const string DEFAULT_MODEL = 'gpt-4o';

    public function __construct(
        private Scenario $scenario,
        private Workspace $workspace,
    ) {}

    #[Override]
    public function run(Step $step): ConsoleRun
    {
        ConsoleTester::enter($step, $this->workspace);
        $compatKernel = new CompatKernel($this->workspace->resolve('kernel'), $this->bundleConfig(), $this->scenario->services());

        try {
            return ConsoleTester::run(new Application($compatKernel), $step, $this->workspace);
        } finally {
            $compatKernel->shutdown();
        }
    }

    public function bootedKernel(): KernelInterface
    {
        $compatKernel = new CompatKernel($this->workspace->resolve('kernel'), $this->bundleConfig(), $this->scenario->services());
        $compatKernel->boot();

        return $compatKernel;
    }

    /**
     * @return array<string, mixed>
     */
    private function bundleConfig(): array
    {
        $config = ExpandedConfig::of($this->scenario->config(), $this->workspace);

        return \array_key_exists('model', $config) ? $config : ['model' => self::DEFAULT_MODEL, ...$config];
    }
}
