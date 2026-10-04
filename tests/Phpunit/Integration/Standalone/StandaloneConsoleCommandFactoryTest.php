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
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use stdClass;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpServeCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\ProviderBridgeException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnresolvableAuditCommandException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnresolvableMcpServeCommandException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneConsoleCommandFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneContainerFactory;

final class StandaloneConsoleCommandFactoryTest extends TestCase
{
    private string $cacheDir;

    #[Override]
    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir().'/ssa-cmd-'.bin2hex(random_bytes(6));
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
     * @throws UnresolvableAuditCommandException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_wraps_the_invokable_audit_command_under_its_name_and_alias(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $this->cacheDir,
        );

        $command = (new StandaloneConsoleCommandFactory())->create($containerBuilder);

        self::assertSame('audit:run', $command->getName());
        self::assertContains('audit', $command->getAliases());
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws UnresolvableAuditCommandException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_wrapped_command_leaves_the_banner_to_the_application(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $this->cacheDir,
        );

        $commandTester = new CommandTester((new StandaloneConsoleCommandFactory())->create($containerBuilder));
        $commandTester->execute(['project-path' => __DIR__.'/Fixture', '--dry-run' => true]);

        $display = $commandTester->getDisplay();
        self::assertStringContainsString('Project:', $display);
        self::assertStringNotContainsString('SECURITY AUDITOR', $display);
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws UnresolvableMcpServeCommandException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_wraps_the_invokable_mcp_server_command_under_its_name(): void
    {
        $containerBuilder = (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $this->cacheDir,
        );

        self::assertSame('mcp:serve', (new StandaloneConsoleCommandFactory())->createMcpServer($containerBuilder)->getName());
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws UnresolvableAuditCommandException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_describes_the_audit_command_exactly_as_the_container_builds_it(): void
    {
        $command = (new StandaloneConsoleCommandFactory())->create($this->containerBuilder());

        self::assertEquals($this->describedSurface($command), $this->describedSurface((new StandaloneConsoleCommandFactory())->describe(AuditCommand::class)));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws UnresolvableMcpServeCommandException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_it_describes_the_mcp_server_command_exactly_as_the_container_builds_it(): void
    {
        $command = (new StandaloneConsoleCommandFactory())->createMcpServer($this->containerBuilder());

        self::assertEquals($this->describedSurface($command), $this->describedSurface((new StandaloneConsoleCommandFactory())->describe(McpServeCommand::class)));
    }

    /**
     * @throws UnresolvableMcpServeCommandException
     */
    public function test_it_rejects_a_container_whose_mcp_server_service_is_not_the_mcp_server_command(): void
    {
        $this->expectException(UnresolvableMcpServeCommandException::class);

        $containerBuilder = new ContainerBuilder();
        $containerBuilder->register(McpServeCommand::class, stdClass::class)->setPublic(true);
        $containerBuilder->compile(true);

        (new StandaloneConsoleCommandFactory())->createMcpServer($containerBuilder);
    }

    /**
     * @throws UnresolvableAuditCommandException
     */
    public function test_it_rejects_a_container_whose_audit_service_is_not_the_audit_command(): void
    {
        $this->expectException(UnresolvableAuditCommandException::class);

        $containerBuilder = new ContainerBuilder();
        $containerBuilder->register(AuditCommand::class, stdClass::class)->setPublic(true);
        $containerBuilder->compile(true);

        (new StandaloneConsoleCommandFactory())->create($containerBuilder);
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    private function containerBuilder(): ContainerBuilder
    {
        return (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'http://localhost']]])),
            $this->cacheDir,
        );
    }

    /**
     * @return array{?string, array<mixed>, string, string, InputDefinition}
     */
    private function describedSurface(Command $command): array
    {
        return [$command->getName(), $command->getAliases(), $command->getDescription(), $command->getHelp(), $command->getDefinition()];
    }
}
