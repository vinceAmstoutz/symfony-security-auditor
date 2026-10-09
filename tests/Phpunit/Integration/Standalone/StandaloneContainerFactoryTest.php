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
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
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
    #[DataProvider('cacheDirectoriesHoldingPercentSigns')]
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_takes_a_cache_directory_holding_percent_signs_literally(string $cacheDir): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $cacheDir,
        );

        self::assertSame(
            [$cacheDir, $cacheDir],
            [$containerBuilder->getParameter('kernel.cache_dir'), $containerBuilder->getParameter('kernel.build_dir')],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function cacheDirectoriesHoldingPercentSigns(): iterable
    {
        yield 'a pair naming no parameter' => ['/tmp/%x%/cache'];
        yield 'a doubled percent sign' => ['/tmp/a%%b/cache'];
        yield 'an environment placeholder' => ['/tmp/%env(HOME)%/cache'];
    }

    /**
     * @param array<array-key, mixed> $auditConfig
     * @param non-empty-list<string>  $path
     *
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[DataProvider('freeTextHoldingPercentSigns')]
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_takes_free_text_holding_an_unresolvable_percent_pair_literally(array $auditConfig, string $parameter, array $path, string $expected): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig($auditConfig, new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $this->cacheDir,
        );

        $value = $containerBuilder->getParameter($parameter);
        foreach ($path as $key) {
            self::assertIsArray($value);
            $value = $value[$key];
        }

        self::assertSame($expected, $value);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string, non-empty-list<string>, string}>
     */
    public static function freeTextHoldingPercentSigns(): iterable
    {
        $pattern = static fn (string $regex, string $description): array => ['scan' => ['custom_risk_patterns' => ['php' => ['sprintf_sql' => ['regex' => $regex, 'description' => $description]]]]];

        yield 'a risk pattern matching printf placeholders' => [$pattern('/sprintf\(.*%s.*%d/', 'sql built with sprintf'), 'symfony_security_auditor.scan.custom_risk_patterns', ['php', 'sprintf_sql', 'regex'], '/sprintf\(.*%s.*%d/'];
        yield 'a risk pattern description' => [$pattern('/x/', 'a discount between 50%-60% is fine'), 'symfony_security_auditor.scan.custom_risk_patterns', ['php', 'sprintf_sql', 'description'], 'a discount between 50%-60% is fine'];
        yield 'an additional scrubbing pattern' => [['scan' => ['secret_scrubbing' => ['additional_patterns' => ['/key=%secret%/']]]], 'symfony_security_auditor.scan.secret_scrubbing.additional_patterns', ['0'], '/key=%secret%/'];
        yield 'a doubled percent sign, which the container still reads as one' => [$pattern('/100%%/', 'd'), 'symfony_security_auditor.scan.custom_risk_patterns', ['php', 'sprintf_sql', 'regex'], '/100%/'];
        yield 'a reference to a parameter the container has' => [$pattern('/x/', 'in %kernel.project_dir%'), 'symfony_security_auditor.scan.custom_risk_patterns', ['php', 'sprintf_sql', 'description'], 'in '.getcwd()];
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
    public function test_it_still_reads_an_environment_placeholder_in_free_text(): void
    {
        putenv('SSA_FREE_TEXT_TEAM=platform');

        try {
            $containerBuilder = (new StandaloneContainerFactory())->create(
                new StandaloneConfig(
                    ['scan' => ['secret_scrubbing' => ['additional_patterns' => ['/%env(SSA_FREE_TEXT_TEAM)%-%x%/']]]],
                    new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]]),
                ),
                $this->cacheDir,
            );

            self::assertSame(['/platform-%x%/'], $containerBuilder->getParameter('symfony_security_auditor.scan.secret_scrubbing.additional_patterns'));
        } finally {
            putenv('SSA_FREE_TEXT_TEAM');
        }
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
    public function test_it_takes_custom_skill_instructions_holding_an_unresolvable_percent_pair_literally(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                ['audit' => ['custom_skills' => ['pricing' => ['file_type' => 'controller', 'instructions' => 'A discount between 50%-60% is fine.']]]],
                new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]]),
            ),
            $this->cacheDir,
        );

        $configuredAttackerSkill = $containerBuilder->getDefinition('security_auditor.custom_skill.0')->getArgument(0);
        self::assertInstanceOf(Definition::class, $configuredAttackerSkill);
        self::assertSame('A discount between 50%-60% is fine.', $containerBuilder->getParameterBag()->unescapeValue($configuredAttackerSkill->getArgument(2)));
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
    public function test_it_takes_a_working_directory_holding_percent_signs_literally(): void
    {
        $workingDirectory = sys_get_temp_dir().'/ssa-%x%-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($workingDirectory);

        try {
            chdir($workingDirectory);

            $containerBuilder = (new StandaloneContainerFactory())->create(
                new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
                $this->cacheDir,
            );

            self::assertSame(getcwd(), $containerBuilder->getParameter('kernel.project_dir'));
        } finally {
            chdir(sys_get_temp_dir());
            (new Filesystem())->remove($workingDirectory);
        }
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
     * @param array<array-key, mixed>         $auditConfig
     * @param array<string, float|int|string> $expectedOptions
     *
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[DataProvider('httpClientOptionCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_platform_reaches_the_provider_through_a_client_that_waits_as_long_as_configured(?float $configured, array $auditConfig, array $expectedOptions): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['ollama' => ['endpoint' => 'http://localhost:11434']], 'ollama');
        $standaloneConfig = null === $configured ? new StandaloneConfig($auditConfig, $standalonePlatformConfig) : new StandaloneConfig($auditConfig, $standalonePlatformConfig, httpTimeout: $configured);

        $containerBuilder = (new StandaloneContainerFactory())->create($standaloneConfig, $this->cacheDir);

        self::assertSame([$expectedOptions], $containerBuilder->getDefinition('http_client')->getArguments());
    }

    /**
     * @return iterable<string, array{?float, array<array-key, mixed>, array<string, float|int|string>}>
     */
    public static function httpClientOptionCases(): iterable
    {
        yield 'ten minutes when none is configured' => [null, [], ['timeout' => 600.0, 'max_duration' => 0]];
        yield 'what the configuration sets' => [1800.0, [], ['timeout' => 1800.0, 'max_duration' => 0]];
        yield 'no proxy when offline only' => [null, ['privacy' => ['offline_only' => true]], ['timeout' => 600.0, 'max_duration' => 0, 'no_proxy' => '*']];
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
    public function test_offline_only_keeps_the_provider_client_away_from_a_proxy_in_the_environment(): void
    {
        $proxy = stream_socket_server('tcp://127.0.0.1:0');
        self::assertIsResource($proxy);
        $proxyAddress = stream_socket_get_name($proxy, false);
        self::assertIsString($proxyAddress);
        $_SERVER['http_proxy'] = \sprintf('http://%s', $proxyAddress);
        $_SERVER['no_proxy'] = '';
        $_SERVER['NO_PROXY'] = '';

        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                ['privacy' => ['offline_only' => true]],
                new StandalonePlatformConfig(['ollama' => ['endpoint' => 'http://localhost:11434']], 'ollama'),
            ),
            $this->cacheDir,
        );
        $options = $containerBuilder->getDefinition('http_client')->getArguments()[0];
        self::assertIsArray($options);

        $failure = null;

        try {
            HttpClient::create($options)->request('GET', 'http://127.0.0.1:1/', ['timeout' => 0.5])->getStatusCode();
        } catch (TransportExceptionInterface $transportException) {
            $failure = $transportException;
        }

        $readable = [$proxy];
        $write = null;
        $except = null;

        self::assertInstanceOf(TransportExceptionInterface::class, $failure);
        self::assertSame(0, stream_select($readable, $write, $except, 0), 'the request reached the proxy');
    }

    /**
     * @param array<string, mixed>            $platform
     * @param array<string, float|int|string> $expectedOptions
     *
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[DataProvider('offlineOnlyPlatformCases')]
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_offline_only_leaves_the_proxy_of_the_environment_to_an_endpoint_that_is_not_on_the_loopback_interface(array $platform, array $expectedOptions): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(['privacy' => ['offline_only' => true]], new StandalonePlatformConfig($platform, 'ollama')),
            $this->cacheDir,
        );

        self::assertSame([$expectedOptions], $containerBuilder->getDefinition('http_client')->getArguments());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, array<string, float|int|string>}>
     */
    public static function offlineOnlyPlatformCases(): iterable
    {
        $withoutBypass = ['timeout' => 600.0, 'max_duration' => 0];
        $withBypass = ['timeout' => 600.0, 'max_duration' => 0, 'no_proxy' => '*'];

        yield 'a loopback name' => [['ollama' => ['endpoint' => 'http://localhost:11434']], $withBypass];
        yield 'a loopback ipv4 address' => [['ollama' => ['endpoint' => 'http://127.0.0.1:11434']], $withBypass];
        yield 'a loopback ipv6 address' => [['ollama' => ['endpoint' => 'http://[::1]:11434']], $withBypass];
        yield 'two loopback endpoints' => [['ollama' => ['endpoint' => 'http://localhost:11434'], 'generic' => ['gw' => ['base_url' => 'http://127.0.0.1:8080']]], $withBypass];
        yield 'a private-range address' => [['ollama' => ['endpoint' => 'http://192.168.1.50:11434']], $withoutBypass];
        yield 'a private network name' => [['ollama' => ['endpoint' => 'http://workstation.local:11434']], $withoutBypass];
        yield 'a private-range address beside a loopback endpoint' => [['ollama' => ['endpoint' => 'http://localhost:11434'], 'generic' => ['gw' => ['base_url' => 'http://10.0.0.2:8080']]], $withoutBypass];
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
    public function test_offline_only_still_reaches_a_private_range_endpoint_through_the_proxy_of_the_environment(): void
    {
        $proxy = stream_socket_server('tcp://127.0.0.1:0');
        self::assertIsResource($proxy);
        $proxyAddress = stream_socket_get_name($proxy, false);
        self::assertIsString($proxyAddress);
        $_SERVER['http_proxy'] = \sprintf('http://%s', $proxyAddress);
        $_SERVER['no_proxy'] = '';
        $_SERVER['NO_PROXY'] = '';

        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig(
                ['privacy' => ['offline_only' => true]],
                new StandalonePlatformConfig(['ollama' => ['endpoint' => 'http://192.168.1.50:11434']], 'ollama'),
            ),
            $this->cacheDir,
        );
        $options = $containerBuilder->getDefinition('http_client')->getArguments()[0];
        self::assertIsArray($options);

        try {
            HttpClient::create($options)->request('GET', 'http://192.168.1.50:11434/', ['timeout' => 0.5])->getStatusCode();
        } catch (TransportExceptionInterface) {
            $readable = [$proxy];
            $write = null;
            $except = null;

            self::assertSame(1, stream_select($readable, $write, $except, 0), 'the request did not reach the proxy');

            return;
        }

        self::fail('the proxy never answered, so the request cannot have succeeded');
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
