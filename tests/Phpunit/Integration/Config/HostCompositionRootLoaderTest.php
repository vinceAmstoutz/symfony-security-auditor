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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Config;

use JsonException;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ParameterBag\EnvPlaceholderParameterBag;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EscalatingAttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditExecutionConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRateLimitConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CoreCompositionRoot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HostCompositionRootLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\SymfonyProfile;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;

final class HostCompositionRootLoaderTest extends TestCase
{
    /**
     * @throws JsonException
     * @throws InvalidAuditExecutionConfigurationException
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_a_host_wires_the_audit_graph_without_instantiating_the_bundle(): void
    {
        $containerBuilder = $this->load([]);

        self::assertTrue($containerBuilder->hasDefinition(AuditCommand::class));
    }

    /**
     * @throws JsonException
     * @throws InvalidAuditExecutionConfigurationException
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_the_llm_client_port_is_aliased_to_the_attacker_client(): void
    {
        $containerBuilder = $this->load([]);

        self::assertSame('security_auditor.attacker_client', (string) $containerBuilder->getAlias(LLMClientInterface::class));
    }

    /**
     * @throws JsonException
     * @throws InvalidAuditExecutionConfigurationException
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_configuration_still_selects_implementations_through_the_host_path(): void
    {
        $containerBuilder = $this->load(['cache' => ['enabled' => false]]);

        self::assertSame(NullAttackerCache::class, (string) $containerBuilder->getAlias(AttackerCacheInterface::class));
    }

    /**
     * @throws JsonException
     * @throws InvalidAuditExecutionConfigurationException
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_cache_enabled_selects_the_filesystem_attacker_cache(): void
    {
        $containerBuilder = $this->load(['cache' => ['enabled' => true]]);

        self::assertSame(FilesystemAttackerCache::class, (string) $containerBuilder->getAlias(AttackerCacheInterface::class));
    }

    /**
     * @throws JsonException
     * @throws InvalidAuditExecutionConfigurationException
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_escalation_swaps_the_attacker_agent_for_the_escalating_one(): void
    {
        $containerBuilder = $this->load(['audit' => ['escalation' => ['enabled' => true]]]);

        self::assertSame(EscalatingAttackerAgent::class, (string) $containerBuilder->getAlias(AttackerAgentInterface::class));
    }

    /**
     * @param array<array-key, mixed> $auditConfig
     *
     * @throws JsonException
     * @throws InvalidAuditExecutionConfigurationException
     * @throws InvalidRateLimitConfigurationException
     */
    private function load(array $auditConfig): ContainerBuilder
    {
        $cacheDir = sys_get_temp_dir().'/ssa-host-'.bin2hex(random_bytes(6));

        $containerBuilder = new ContainerBuilder(new EnvPlaceholderParameterBag([
            'kernel.cache_dir' => $cacheDir,
            'kernel.build_dir' => $cacheDir,
            'kernel.project_dir' => $cacheDir,
            'kernel.environment' => 'prod',
            'kernel.debug' => false,
        ]));
        $containerBuilder->register('logger', NullLogger::class);
        $containerBuilder->register(ClockInterface::class, NativeClock::class);

        (new HostCompositionRootLoader(new CoreCompositionRoot(new SymfonyProfile())))->load($auditConfig, $containerBuilder, 'prod');

        return $containerBuilder;
    }
}
