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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Standalone;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Bridge\Ollama\Factory as OllamaFactory;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PricingPlatformPass;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\ProviderBridgeException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneContainerFactory;

final class StandaloneContainerFactoryTest extends TestCase
{
    private string $cacheDir;

    #[Override]
    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir().'/ssa-container-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->cacheDir);
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_builds_a_container_exposing_a_fully_wired_audit_command(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $this->cacheDir,
        );

        self::assertInstanceOf(AuditCommand::class, $containerBuilder->get(AuditCommand::class));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    public function test_offline_only_refuses_to_boot_against_a_remote_platform(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('"anthropic"');

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                ['privacy' => ['offline_only' => true]],
                new StandalonePlatformConfig(['anthropic' => ['api_key' => 'sk-secret']]),
            ),
            $this->cacheDir,
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_offline_only_boots_against_a_local_platform(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                ['privacy' => ['offline_only' => true]],
                new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]]),
            ),
            $this->cacheDir,
        );

        self::assertInstanceOf(AuditCommand::class, $containerBuilder->get(AuditCommand::class));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_configures_a_non_debug_kernel_with_a_public_event_dispatcher(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $this->cacheDir,
        );

        self::assertSame(getcwd(), $containerBuilder->getParameter('kernel.project_dir'));
        self::assertFalse($containerBuilder->getParameter('kernel.debug'));
        self::assertInstanceOf(EventDispatcher::class, $containerBuilder->get('event_dispatcher'));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_provides_every_service_the_ollama_platform_demands_outright(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['ollama' => ['endpoint' => 'http://localhost:11434']], 'ollama')),
            $this->cacheDir,
        );

        $platform = $containerBuilder->get(PlatformInterface::class);
        self::assertInstanceOf(PlatformInterface::class, $platform);

        self::assertSame(OllamaFactory::STUB_RESPONSE, $platform->invoke('llama3.3', 'ping')->asText());
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[DataProvider('httpTimeouts')]
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_platform_reaches_the_provider_through_a_client_that_waits_as_long_as_configured(?float $configured, float $expected): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['ollama' => ['endpoint' => 'http://localhost:11434']], 'ollama');
        $standaloneConfig = null === $configured ? new StandaloneConfig([], $standalonePlatformConfig) : new StandaloneConfig([], $standalonePlatformConfig, httpTimeout: $configured);

        $containerBuilder = (new StandaloneContainerFactory())->create($standaloneConfig, $this->cacheDir);

        self::assertSame([['timeout' => $expected, 'max_duration' => 0]], $containerBuilder->getDefinition('http_client')->getArguments());
    }

    /**
     * @return iterable<string, array{?float, float}>
     */
    public static function httpTimeouts(): iterable
    {
        yield 'ten minutes when none is configured' => [null, 600.0];
        yield 'what the configuration sets' => [1800.0, 1800.0];
    }

    /**
     * @param array<string, mixed> $platform
     *
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[DataProvider('servingPlatformCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_publishes_the_platform_the_audit_runs_against_for_pricing(array $platform, ?string $provider, string $expectedPlatform): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig($platform, $provider)),
            $this->cacheDir,
        );

        self::assertSame($expectedPlatform, $containerBuilder->getParameter(PricingPlatformPass::PARAMETER));
    }

    /** @return iterable<string, array{array<string, mixed>, ?string, string}> */
    public static function servingPlatformCases(): iterable
    {
        yield 'the only platform configured' => [['ollama' => ['endpoint' => 'http://localhost:11434']], null, 'ollama'];
        yield 'the instance the provider selects' => [
            ['generic' => ['primary' => ['base_url' => 'http://a'], 'secondary' => ['base_url' => 'http://b']]],
            'generic.secondary',
            'generic',
        ];
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_aliases_the_selected_provider_when_several_are_configured(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                [],
                new StandalonePlatformConfig(
                    ['generic' => ['primary' => ['base_url' => 'http://a'], 'secondary' => ['base_url' => 'http://b']]],
                    'generic.secondary',
                ),
            ),
            $this->cacheDir,
        );

        self::assertInstanceOf(PlatformInterface::class, $containerBuilder->get(PlatformInterface::class));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    public function test_it_rejects_a_selector_absent_from_the_platform_block(): void
    {
        $this->expectException(UnknownPlatformProviderException::class);
        $this->expectExceptionMessage('The selected provider "mistral" is not present in the "platform:" block of your config.');

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://a']]], 'mistral')),
            $this->cacheDir,
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    public function test_it_does_not_offer_instances_for_a_platform_configured_without_one(): void
    {
        $this->expectException(UnknownPlatformProviderException::class);
        $this->expectExceptionMessage('The selected provider "ollama.typo" is not present in the "platform:" block of your config.');

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(
                ['ollama' => ['endpoint' => 'http://127.0.0.1:11434']],
                'ollama.typo',
            )),
            $this->cacheDir,
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    public function test_it_names_the_configured_instances_when_the_selected_one_does_not_exist(): void
    {
        $this->expectException(UnknownPlatformProviderException::class);
        $this->expectExceptionMessage('The "generic" platform has no "typo" instance. Configured instances: primary.');

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(
                ['generic' => ['primary' => ['base_url' => 'http://a']]],
                'generic.typo',
            )),
            $this->cacheDir,
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    public function test_it_names_the_configured_instances_when_an_instance_keyed_platform_is_selected_without_one(): void
    {
        $this->expectException(UnknownPlatformProviderException::class);
        $this->expectExceptionMessage('The "generic" platform is configured per instance, so "provider: generic" does not select one. Use "generic.<instance>" instead. Configured instances: primary, secondary.');

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(
                ['generic' => ['primary' => ['base_url' => 'http://a'], 'secondary' => ['base_url' => 'http://b']]],
                'generic',
            )),
            $this->cacheDir,
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_resolves_environment_variable_placeholders_in_the_audit_configuration(): void
    {
        putenv('SSA_TEST_MODEL=claude-opus-5');

        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                ['model' => '%env(SSA_TEST_MODEL)%'],
                new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]]),
            ),
            $this->cacheDir,
        );

        self::assertSame('claude-opus-5', $containerBuilder->getParameter('symfony_security_auditor.attacker_model'));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    public function test_it_rejects_several_platforms_without_a_selector(): void
    {
        $this->expectException(AmbiguousPlatformException::class);

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                [],
                new StandalonePlatformConfig(['generic' => ['primary' => ['base_url' => 'http://a'], 'secondary' => ['base_url' => 'http://b']]]),
            ),
            $this->cacheDir,
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    public function test_a_platform_whose_bridge_is_not_installed_is_answered_with_the_init_command(): void
    {
        $this->expectException(ProviderBridgeException::class);
        $this->expectExceptionMessage('Run "symfony-security-auditor init --provider=anthropic" to download it');

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['anthropic' => ['api_key' => 'sk-test']])),
            $this->cacheDir,
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    public function test_the_init_advice_names_the_platform_whose_bridge_is_missing_not_the_selected_provider(): void
    {
        $this->expectException(ProviderBridgeException::class);
        $this->expectExceptionMessage('init --provider=anthropic"');

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']], 'anthropic' => ['api_key' => 'sk-test']], 'generic.default')),
            $this->cacheDir,
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    public function test_any_other_failure_of_the_bundle_keeps_its_own_exception(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => 'not a platform block'])),
            $this->cacheDir,
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_announces_the_project_config_layered_over_the_user_config_after_the_other_notices(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                ['audit' => ['reviewer_max_concurrent' => 2, 'reviewer_tools_enabled' => true, 'attacker_max_concurrent' => 2, 'structured_collection' => false]],
                new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]]),
                '/repo/.symfony-security-auditor.yaml',
            ),
            $this->cacheDir,
        );

        self::assertSame(
            [
                'audit.reviewer_max_concurrent > 1 has no effect while audit.reviewer_tools_enabled is true: tool-using reviews run sequentially. Drop reviewer_tools_enabled to review concurrently, or set reviewer_max_concurrent: 1 to silence this.',
                'audit.attacker_max_concurrent > 1 has no effect while audit.structured_collection is false: the JSON-parsing attacker analyses chunks sequentially. Re-enable structured_collection to analyse concurrently, or set attacker_max_concurrent: 1 to silence this.',
                'Project config /repo/.symfony-security-auditor.yaml is layered over your user config: the audited repository may tune the audit through it (paths, profile, models, a tighter budget), never the platform and its credentials, the cache, privacy, custom skills, secret scrubbing, custom risk patterns or imported SARIF.',
            ],
            $containerBuilder->getParameter('symfony_security_auditor.config_notices'),
        );
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_announces_no_project_config_when_none_was_layered_in(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $this->cacheDir,
        );

        self::assertSame([], $containerBuilder->getParameter('symfony_security_auditor.config_notices'));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_a_project_config_path_containing_a_percent_is_escaped_so_it_does_not_abort_the_container(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                [],
                new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]]),
                '/repo/%weird%/.symfony-security-auditor.yaml',
            ),
            $this->cacheDir,
        );

        self::assertSame(
            ['Project config /repo/%weird%/.symfony-security-auditor.yaml is layered over your user config: the audited repository may tune the audit through it (paths, profile, models, a tighter budget), never the platform and its credentials, the cache, privacy, custom skills, secret scrubbing, custom risk patterns or imported SARIF.'],
            $containerBuilder->getParameter('symfony_security_auditor.config_notices'),
        );
    }
}
