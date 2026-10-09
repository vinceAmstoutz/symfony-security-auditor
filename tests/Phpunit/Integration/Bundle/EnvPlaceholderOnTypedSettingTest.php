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

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\BaseNode;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\PrototypedArrayNode;
use Symfony\Component\DependencyInjection\Compiler\MergeExtensionConfigurationPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ParameterBag\EnvPlaceholderParameterBag;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;

final class EnvPlaceholderOnTypedSettingTest extends TestCase
{
    private const string PLACEHOLDER = '%env(SSA_VALUE)%';

    private const string ENTRY = 'entry';

    #[Override]
    protected function tearDown(): void
    {
        BaseNode::resetPlaceholders();
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('settingsReadWhileTheContainerIsBuilt')]
    public function test_a_placeholder_on_a_setting_read_while_the_container_is_built_is_refused_naming_the_key(array $config, string $path): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(\sprintf('"%s"', $path));

        $this->mergeConfiguration($config);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function settingsReadWhileTheContainerIsBuilt(): iterable
    {
        yield 'a cost cap' => [['audit' => ['budget' => ['max_cost_usd' => '%env(float:SSA_MAX_COST)%']]], 'symfony_security_auditor.audit.budget.max_cost_usd'];
        yield 'a minimum score' => [['audit' => ['min_score' => '%env(int:SSA_MIN_SCORE)%']], 'symfony_security_auditor.audit.min_score'];
        yield 'the tools switch' => [['audit' => ['tools_enabled' => '%env(bool:SSA_TOOLS)%']], 'symfony_security_auditor.audit.tools_enabled'];
        yield 'the cache switch' => [['cache' => ['enabled' => '%env(bool:SSA_CACHE)%']], 'symfony_security_auditor.cache.enabled'];
        yield 'the offline guard' => [['privacy' => ['offline_only' => '%env(bool:SSA_OFFLINE)%']], 'symfony_security_auditor.privacy.offline_only'];
        yield 'the failing risk level' => [['audit' => ['fail_on' => '%env(SSA_FAIL_ON)%']], 'symfony_security_auditor.audit.fail_on'];
    }

    public function test_a_placeholder_on_a_string_setting_is_left_for_the_container_to_resolve(): void
    {
        $containerBuilder = $this->mergeConfiguration(['model' => '%env(SSA_MODEL)%']);

        $attackerModel = $containerBuilder->getParameter('symfony_security_auditor.attacker_model');
        self::assertIsString($attackerModel);
        self::assertStringStartsWith('env_', $attackerModel);
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('everySetting')]
    public function test_a_placeholder_on_any_setting_is_either_taken_or_refused_with_a_configuration_error(array $config): void
    {
        $failure = null;

        try {
            $this->mergeConfiguration($config);
        } catch (Throwable $throwable) {
            $failure = $throwable;
        }

        self::assertThat($failure, self::logicalOr(self::isNull(), self::isInstanceOf(InvalidConfigurationException::class)));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function everySetting(): iterable
    {
        $treeBuilder = new TreeBuilder('symfony_security_auditor');
        (new AuditConfigurationDefinition())->defineChildren($treeBuilder->getRootNode()->children());
        $node = $treeBuilder->buildTree();
        self::assertInstanceOf(ArrayNode::class, $node);

        foreach ($node->getChildren() as $name => $child) {
            foreach (self::leafPaths($child, [$name]) as $path) {
                yield implode('.', $path) => [self::configurationHolding($path)];
            }
        }
    }

    /**
     * @param non-empty-list<string> $path
     *
     * @return iterable<non-empty-list<string>>
     */
    private static function leafPaths(NodeInterface $node, array $path): iterable
    {
        if ($node instanceof PrototypedArrayNode) {
            yield from self::leafPaths($node->getPrototype(), [...$path, self::ENTRY]);

            return;
        }

        if (!$node instanceof ArrayNode) {
            yield $path;

            return;
        }

        foreach ($node->getChildren() as $name => $child) {
            yield from self::leafPaths($child, [...$path, $name]);
        }
    }

    /**
     * @param non-empty-list<string> $path
     *
     * @return array<string, mixed>
     */
    private static function configurationHolding(array $path): array
    {
        $leaf = array_pop($path);
        $configuration = [$leaf => self::PLACEHOLDER];

        if ('custom_skills' === ($path[1] ?? null)) {
            $configuration += ['file_type' => 'controller', 'instructions' => 'Look for secrets.'];
        }

        foreach (array_reverse($path) as $key) {
            $configuration = [$key => $configuration];
        }

        return $configuration;
    }

    /**
     * @param array<string, mixed> $config
     */
    private function mergeConfiguration(array $config): ContainerBuilder
    {
        $containerBuilder = new ContainerBuilder(new EnvPlaceholderParameterBag([
            'kernel.cache_dir' => '/tmp/ssa-cache',
            'kernel.build_dir' => '/tmp/ssa-cache',
            'kernel.project_dir' => '/tmp/ssa-project',
            'kernel.environment' => 'test',
            'kernel.debug' => true,
        ]));
        $extension = (new SymfonySecurityAuditorBundle())->getContainerExtension();
        self::assertNotNull($extension);
        $containerBuilder->registerExtension($extension);
        $containerBuilder->loadFromExtension('symfony_security_auditor', $config);

        (new MergeExtensionConfigurationPass())->process($containerBuilder);

        return $containerBuilder;
    }
}
