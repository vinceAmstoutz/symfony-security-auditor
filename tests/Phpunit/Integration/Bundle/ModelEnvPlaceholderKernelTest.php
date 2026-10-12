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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bundle;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Test\InMemoryPlatform;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Test\TestContainer;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Kernel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;

final class ModelEnvPlaceholderKernelTest extends TestCase
{
    private const array MODEL_VARIABLES = [
        'SSA_ATTACKER_MODEL' => 'gpt-4.1',
        'SSA_REVIEWER_MODEL' => 'gpt-4o-mini',
        'SSA_CHEAP_MODEL' => 'gpt-4.1-nano',
    ];

    private string $tmpDir;

    private ?Kernel $bootedKernel = null;

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_a_kernel_reads_the_attacker_reviewer_and_cheap_models_from_the_environment(): void
    {
        $testContainer = $this->boot()->getContainer()->get('test.service_container');
        self::assertInstanceOf(TestContainer::class, $testContainer);

        self::assertSame(
            ['gpt-4.1', 'gpt-4o-mini', 'gpt-4.1-nano'],
            array_map(
                static fn (string $client): string => self::client($testContainer, $client)->model(),
                ['security_auditor.attacker_client', 'security_auditor.reviewer_client', 'security_auditor.cheap_attacker_client'],
            ),
        );
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/model_env_placeholder_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);

        foreach (self::MODEL_VARIABLES as $name => $value) {
            $_SERVER[$name] = $value;
        }
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->bootedKernel?->shutdown();
        $this->bootedKernel = null;

        foreach (array_keys(self::MODEL_VARIABLES) as $name) {
            unset($_SERVER[$name]);
        }

        (new Filesystem())->remove($this->tmpDir);
    }

    private static function client(TestContainer $testContainer, string $id): LLMClientInterface
    {
        $client = $testContainer->get($id);
        self::assertInstanceOf(LLMClientInterface::class, $client);

        return $client;
    }

    private function boot(): Kernel
    {
        $kernel = new class('test', true, $this->tmpDir) extends Kernel {
            public function __construct(string $environment, bool $debug, private readonly string $tmpDir)
            {
                parent::__construct($environment, $debug);
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
                $loader->load(static function (ContainerBuilder $containerBuilder): void {
                    $containerBuilder->loadFromExtension('framework', [
                        'secret' => 'test',
                        'http_method_override' => false,
                        'handle_all_throwables' => true,
                        'test' => true,
                        'php_errors' => ['log' => true],
                    ]);
                    $containerBuilder->loadFromExtension('symfony_security_auditor', [
                        'model' => 'gpt-4o',
                        'attacker_model' => '%env(SSA_ATTACKER_MODEL)%',
                        'reviewer_model' => '%env(SSA_REVIEWER_MODEL)%',
                        'audit' => ['escalation' => ['enabled' => true, 'cheap_model' => '%env(SSA_CHEAP_MODEL)%']],
                    ]);
                    $containerBuilder->register(PlatformInterface::class, InMemoryPlatform::class)
                        ->setArguments(['stub-response'])
                        ->setPublic(true);
                });
            }

            #[Override]
            public function getProjectDir(): string
            {
                return $this->tmpDir;
            }

            #[Override]
            public function getCacheDir(): string
            {
                return $this->tmpDir.'/cache';
            }

            #[Override]
            public function getLogDir(): string
            {
                return $this->tmpDir.'/log';
            }
        };

        $kernel->boot();

        $this->bootedKernel = $kernel;

        return $kernel;
    }
}
