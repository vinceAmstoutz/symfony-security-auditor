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
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Kernel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\DependencyExpansionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\FixSynthesisStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\PoCSynthesisStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\AnthropicTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\DeepSeekTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\GeminiTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\LlamaTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\MiniMaxTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\MistralTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\OpenAiTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bundle\Fixture\AcmeTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bundle\Fixture\DeduplicationStage;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bundle\Fixture\ExplicitlyTaggedHostStage;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bundle\Fixture\LeadingHostStage;

final class HostAutoconfigurationTest extends TestCase
{
    private const string TAGS_PARAMETER = 'test.captured_extension_point_tags';

    private const string PIPELINE_STAGE_TAG = 'symfony_security_auditor.pipeline_stage';

    private const string TOKEN_ESTIMATOR_TAG = 'symfony_security_auditor.token_estimator';

    private string $tmpDir;

    private ?Kernel $bootedKernel = null;

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_an_autoconfigured_host_stage_joins_the_pipeline_at_its_priority(): void
    {
        $auditPipeline = $this->service($this->boot(), AuditPipeline::class);
        self::assertInstanceOf(AuditPipeline::class, $auditPipeline);

        self::assertSame(
            [
                LeadingHostStage::class,
                IngestionStage::class,
                MappingStage::class,
                DependencyExpansionStage::class,
                AuditStage::class,
                PoCSynthesisStage::class,
                FixSynthesisStage::class,
                DeduplicationStage::class,
                ExplicitlyTaggedHostStage::class,
            ],
            array_map(static fn (object $stage): string => $stage::class, $auditPipeline->stages()),
        );
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_an_autoconfigured_host_token_estimator_wins_for_the_models_it_supports(): void
    {
        $tokenEstimator = $this->service($this->boot(), TokenEstimatorInterface::class);
        self::assertInstanceOf(TokenEstimatorInterface::class, $tokenEstimator);
        $text = str_repeat('a', 4000);

        self::assertSame(AcmeTokenEstimator::ESTIMATE, $tokenEstimator->estimateTokens($text, 'acme-1'));
        self::assertSame((new OpenAiTokenEstimator())->estimateTokens($text, 'gpt-4o'), $tokenEstimator->estimateTokens($text, 'gpt-4o'));
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_each_built_in_stage_and_estimator_keeps_a_single_tag_in_its_registration_order(): void
    {
        $capturedTags = $this->boot()->getContainer()->getParameter(self::TAGS_PARAMETER);

        self::assertSame(
            [
                self::PIPELINE_STAGE_TAG => [
                    LeadingHostStage::class => [[]],
                    DeduplicationStage::class => [[]],
                    ExplicitlyTaggedHostStage::class => [['priority' => -200], []],
                    IngestionStage::class => [[]],
                    MappingStage::class => [[]],
                    DependencyExpansionStage::class => [[]],
                    AuditStage::class => [[]],
                    PoCSynthesisStage::class => [[]],
                    FixSynthesisStage::class => [[]],
                ],
                self::TOKEN_ESTIMATOR_TAG => [
                    AcmeTokenEstimator::class => [[]],
                    AnthropicTokenEstimator::class => [[]],
                    OpenAiTokenEstimator::class => [[]],
                    GeminiTokenEstimator::class => [[]],
                    MistralTokenEstimator::class => [[]],
                    LlamaTokenEstimator::class => [[]],
                    DeepSeekTokenEstimator::class => [[]],
                    MiniMaxTokenEstimator::class => [[]],
                ],
            ],
            $capturedTags,
        );
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/host_autoconfiguration_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->bootedKernel?->shutdown();
        $this->bootedKernel = null;

        (new Filesystem())->remove($this->tmpDir);
    }

    private function service(Kernel $kernel, string $id): object
    {
        $testContainer = $kernel->getContainer()->get('test.service_container');
        self::assertInstanceOf(TestContainer::class, $testContainer);

        return $testContainer->get($id);
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
                    $containerBuilder->loadFromExtension('symfony_security_auditor', ['model' => 'gpt-4o']);
                    $containerBuilder->register(PlatformInterface::class, InMemoryPlatform::class)
                        ->setArguments(['stub-response'])
                        ->setPublic(true);
                    $containerBuilder->addCompilerPass(new class implements CompilerPassInterface {
                        #[Override]
                        public function process(ContainerBuilder $container): void
                        {
                            $container->setParameter('test.captured_extension_point_tags', [
                                'symfony_security_auditor.pipeline_stage' => $container->findTaggedServiceIds('symfony_security_auditor.pipeline_stage'),
                                'symfony_security_auditor.token_estimator' => $container->findTaggedServiceIds('symfony_security_auditor.token_estimator'),
                            ]);
                        }
                    }, PassConfig::TYPE_BEFORE_REMOVING);
                });
                $loader->load(__DIR__.'/Fixture/host_services.yaml');
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
