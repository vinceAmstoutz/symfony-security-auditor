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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\TestCase;
use Symfony\AI\AiBundle\AiBundle;
use Symfony\AI\Platform\Bridge\Generic\Factory as GenericFactory;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Test\TestContainer;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Kernel;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;

/**
 * An application whose `ai.yaml` configures several platforms gets no
 * `PlatformInterface` from `symfony/ai-bundle`, which wires it only for a
 * single platform: the application selects the one to audit with by aliasing
 * the interface to it in its own services.
 */
final class SeveralAiPlatformsEndToEndTest extends TestCase
{
    private const string PRIMARY_BASE_URL = 'https://primary.gateway.example';

    private const string SECONDARY_BASE_URL = 'https://secondary.gateway.example';

    private string $kernelDir;

    private string $fixtureDir;

    private ?Kernel $bootedKernel = null;

    #[MaximumDuration(8000)]
    public function test_an_audit_with_several_platforms_and_none_selected_names_them_and_the_alias_that_selects_one(): void
    {
        $commandTester = $this->auditWith(null);

        self::assertSame(1, $commandTester->getStatusCode());
        self::assertStringContainsString(
            'Several AI platforms are configured (ai.platform.generic.primary, ai.platform.generic.secondary) and none is selected: alias Symfony\AI\Platform\PlatformInterface to the one to audit with under "services:" in config/services.yaml, e.g. "Symfony\AI\Platform\PlatformInterface: \'@ai.platform.generic.primary\'".',
            (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()),
        );
    }

    #[MaximumDuration(8000)]
    public function test_a_dry_run_with_several_platforms_and_none_selected_still_estimates_the_cost(): void
    {
        $commandTester = $this->auditWith(null, ['--dry-run' => true]);

        self::assertSame(0, $commandTester->getStatusCode(), $commandTester->getDisplay());
        self::assertStringNotContainsString('[ERROR]', $commandTester->getDisplay());
    }

    #[MaximumDuration(8000)]
    public function test_an_audit_runs_on_the_platform_the_application_aliases_the_platform_interface_to(): void
    {
        $commandTester = $this->auditWith('ai.platform.generic.secondary');

        self::assertSame(0, $commandTester->getStatusCode(), $commandTester->getDisplay());
        self::assertSame(self::SECONDARY_BASE_URL, GenericFactory::$lastBaseUrl);
        self::assertStringNotContainsString('[ERROR]', $commandTester->getDisplay());
    }

    #[Override]
    protected function setUp(): void
    {
        $base = sys_get_temp_dir().'/several_platforms_e2e_'.uniqid('', true);
        $this->kernelDir = $base.'/kernel';
        $this->fixtureDir = $base.'/fixture';
        GenericFactory::$lastBaseUrl = null;

        $filesystem = new Filesystem();
        $filesystem->mkdir($this->kernelDir);
        $filesystem->dumpFile($this->fixtureDir.'/src/Controller/AdminController.php', "<?php\nnamespace App\\Controller;\nclass AdminController {}\n");
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->bootedKernel?->shutdown();
        $this->bootedKernel = null;
        GenericFactory::$lastBaseUrl = null;
        (new Filesystem())->remove(\dirname($this->kernelDir));
    }

    /**
     * @param array<string, mixed> $options
     */
    private function auditWith(?string $selectedPlatform, array $options = []): CommandTester
    {
        $kernel = new class('test', true, $this->kernelDir, $selectedPlatform) extends Kernel {
            public function __construct(string $environment, bool $debug, private readonly string $kernelDir, private readonly ?string $selectedPlatform)
            {
                parent::__construct($environment, $debug);
            }

            /**
             * @return iterable<AiBundle|FrameworkBundle|SymfonySecurityAuditorBundle>
             */
            #[Override]
            public function registerBundles(): iterable
            {
                yield new FrameworkBundle();
                yield new AiBundle();
                yield new SymfonySecurityAuditorBundle();
            }

            #[Override]
            public function registerContainerConfiguration(LoaderInterface $loader): void
            {
                $selectedPlatform = $this->selectedPlatform;
                $loader->load(static function (ContainerBuilder $containerBuilder) use ($selectedPlatform): void {
                    $containerBuilder->loadFromExtension('framework', ['secret' => 'test', 'http_method_override' => false, 'test' => true]);
                    $containerBuilder->loadFromExtension('ai', ['platform' => ['generic' => [
                        'primary' => ['base_url' => SeveralAiPlatformsEndToEndTest::primaryBaseUrl(), 'api_key' => 'primary-key'],
                        'secondary' => ['base_url' => SeveralAiPlatformsEndToEndTest::secondaryBaseUrl(), 'api_key' => 'secondary-key'],
                    ]]]);
                    $containerBuilder->loadFromExtension('symfony_security_auditor', ['model' => 'gateway-model', 'cache' => ['enabled' => false]]);
                    if (null !== $selectedPlatform) {
                        $containerBuilder->setAlias(PlatformInterface::class, $selectedPlatform);
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
                return $this->kernelDir.'/cache';
            }

            #[Override]
            public function getLogDir(): string
            {
                return $this->kernelDir.'/log';
            }
        };
        $kernel->boot();

        $this->bootedKernel = $kernel;

        $testContainer = $kernel->getContainer()->get('test.service_container');
        self::assertInstanceOf(TestContainer::class, $testContainer);
        $auditCommand = $testContainer->get(AuditCommand::class);
        self::assertInstanceOf(AuditCommand::class, $auditCommand);

        $commandTester = new CommandTester($auditCommand);
        $commandTester->execute(['project-path' => $this->fixtureDir, ...$options], ['interactive' => false]);

        return $commandTester;
    }

    public static function primaryBaseUrl(): string
    {
        return self::PRIMARY_BASE_URL;
    }

    public static function secondaryBaseUrl(): string
    {
        return self::SECONDARY_BASE_URL;
    }
}
