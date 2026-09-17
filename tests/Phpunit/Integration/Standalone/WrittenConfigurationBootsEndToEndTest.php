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

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKeyNormalizer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigPlatformOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigScanOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\StandaloneConfigWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsafeStandaloneConfigWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\YamlStandaloneConfigWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneContainerFactory;

/**
 * Every "init wrote a config the next run cannot build" defect on this branch
 * was caught by a person, not by the suite: each rule class is pinned by
 * hard-coded booleans, and nothing fed what the writer produces back through
 * the loader and the container that has to boot it. This closes that loop, so
 * the next such defect fails here rather than on someone's machine.
 */
final class WrittenConfigurationBootsEndToEndTest extends TestCase
{
    private string $home;

    private string $cacheDir;

    #[Override]
    protected function setUp(): void
    {
        $this->home = sys_get_temp_dir().'/ssa-boot-'.bin2hex(random_bytes(6));
        $this->cacheDir = $this->home.'/cache';
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->home);
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MalformedProjectConfigException
     * @throws MissingBundleExtensionException
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws NonLocalPlatformEndpointException
     * @throws ProjectConfigPlatformOverrideException
     * @throws ProjectConfigScanOverrideException
     * @throws StandaloneConfigWriteException
     * @throws UnknownPlatformProviderException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnresolvableConfigPathException
     * @throws UnsafeStandaloneConfigWriteException
     */
    #[DataProvider('providersInitCanWrite')]
    #[RunInSeparateProcess]
    public function test_the_configuration_init_writes_boots_a_platform(string $typed, ?string $baseUrl): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->home.'/config', $this->cacheDir, $this->home);
        $provider = (new ProviderKeyNormalizer())->normalize($typed);

        (new YamlStandaloneConfigWriter())->write(
            $xdgConfigPathResolver->configFile(),
            (new StandaloneConfigFactory())->create($provider, 'our-model', 'GATEWAY_TOKEN', $baseUrl),
        );

        $standaloneConfig = (new StandaloneConfigLoader(
            $xdgConfigPathResolver,
            new StandalonePlatformConfigResolver(['GATEWAY_TOKEN' => 'a-token']),
        ))->load();

        self::assertInstanceOf(
            PlatformInterface::class,
            (new StandaloneContainerFactory())->create($standaloneConfig, $this->cacheDir)->get(PlatformInterface::class),
        );
    }

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function providersInitCanWrite(): iterable
    {
        yield 'an instance-keyed platform' => ['generic.my_gateway', 'http://localhost'];
        yield 'an instance that folds a hyphen' => ['generic.my-gateway', 'http://localhost'];
        yield 'a numbered instance' => ['generic.42', 'http://localhost'];
        yield 'an instance whose case is preserved' => ['generic.myGateway', 'http://localhost'];
        yield 'a platform that takes a single connection block' => ['ollama', null];
    }
}
