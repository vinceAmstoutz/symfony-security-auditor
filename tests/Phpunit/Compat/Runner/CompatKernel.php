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

use Closure;
use Override;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform\CompatPlatform;

/**
 * A Symfony application with the bundle installed, configured from the
 * scenario, whose `symfony/ai` platform is the scripted provider.
 */
final class CompatKernel extends Kernel
{
    /**
     * @param array<string, mixed>                   $bundleConfig
     * @param (Closure(ContainerBuilder): void)|null $services
     */
    public function __construct(
        private readonly string $kernelDir,
        private readonly array $bundleConfig,
        private readonly ?Closure $services,
    ) {
        parent::__construct('test', true);
    }

    /**
     * @return iterable<FrameworkBundle|SymfonySecurityAuditorBundle>
     */
    #[Override]
    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SymfonySecurityAuditorBundle();
    }

    #[Override]
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $bundleConfig = $this->bundleConfig;
        $services = $this->services;
        $loader->load(static function (ContainerBuilder $containerBuilder) use ($bundleConfig, $services): void {
            $containerBuilder->loadFromExtension('framework', [
                'secret' => 'test',
                'http_method_override' => false,
                'handle_all_throwables' => true,
                'test' => true,
                'validation' => ['email_validation_mode' => 'html5'],
                'php_errors' => ['log' => true],
            ]);
            $containerBuilder->loadFromExtension('symfony_security_auditor', $bundleConfig);
            $containerBuilder->register(PlatformInterface::class, CompatPlatform::class)->setPublic(true);
            $containerBuilder->register('logger', NullLogger::class);

            if ($services instanceof Closure) {
                $services($containerBuilder);
            }
        });
    }

    #[Override]
    public function getProjectDir(): string
    {
        return $this->kernelDir;
    }

    #[Override]
    public function getCacheDir(): string
    {
        return \sprintf('%s/cache', $this->kernelDir);
    }

    #[Override]
    public function getLogDir(): string
    {
        return \sprintf('%s/log', $this->kernelDir);
    }
}
