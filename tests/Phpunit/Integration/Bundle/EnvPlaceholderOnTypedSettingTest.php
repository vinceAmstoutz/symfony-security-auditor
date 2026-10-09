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
use Symfony\Component\DependencyInjection\Compiler\ValidateEnvPlaceholdersPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ParameterBag\EnvPlaceholderParameterBag;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\TypedNodeEnvPlaceholderException;
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

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('choicesCheckedAgainstAFixedList')]
    public function test_a_placeholder_on_a_choice_checked_against_a_fixed_list_is_refused_naming_the_key(array $config, string $path): void
    {
        $this->expectException(TypedNodeEnvPlaceholderException::class);
        $this->expectExceptionMessage(\sprintf('"%s"', $path));

        $this->mergeConfiguration($config);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function choicesCheckedAgainstAFixedList(): iterable
    {
        yield 'the default report format' => [['audit' => ['format' => '%env(SSA_FORMAT)%']], 'symfony_security_auditor.audit.format'];
        yield 'the since closure' => [['audit' => ['since_closure' => '%env(SSA_CLOSURE)%']], 'symfony_security_auditor.audit.since_closure'];
        yield 'an excluded type' => [['audit' => ['excluded_types' => ['sql_injection', '%env(SSA_TYPE)%']]], 'symfony_security_auditor.audit.excluded_types.1'];
        yield 'an included type' => [['audit' => ['included_types' => ['%env(SSA_TYPE)%']]], 'symfony_security_auditor.audit.included_types.0'];
        yield 'the chunking strategy' => [['audit' => ['chunking' => ['strategy' => '%env(SSA_STRATEGY)%']]], 'symfony_security_auditor.audit.chunking.strategy'];
        yield 'the PoC severity floor' => [['audit' => ['poc_synthesis' => ['severity_floor' => '%env(SSA_FLOOR)%']]], 'symfony_security_auditor.audit.poc_synthesis.severity_floor'];
        yield 'the fix severity floor' => [['audit' => ['fix_synthesis' => ['severity_floor' => '%env(SSA_FLOOR)%']]], 'symfony_security_auditor.audit.fix_synthesis.severity_floor'];
    }

    /**
     * @param array<string, mixed> $config
     */
    #[DataProvider('modelSettings')]
    public function test_a_placeholder_on_a_model_setting_is_taken_and_left_for_the_container_to_resolve(array $config, string $parameter): void
    {
        $containerBuilder = $this->mergeConfiguration($config);

        $value = $containerBuilder->getParameter($parameter);
        self::assertIsString($value);
        self::assertStringContainsString('env_', $value);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function modelSettings(): iterable
    {
        yield 'the attacker model' => [['attacker_model' => self::PLACEHOLDER], 'symfony_security_auditor.attacker_model'];
        yield 'the reviewer model' => [['reviewer_model' => self::PLACEHOLDER], 'symfony_security_auditor.reviewer_model'];
        yield 'the cheap escalation model' => [['audit' => ['escalation' => ['enabled' => true, 'cheap_model' => self::PLACEHOLDER]]], 'symfony_security_auditor.cache.cheap_attacker_key_salt'];
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
    public function test_a_placeholder_on_any_setting_is_either_taken_or_refused_by_name(array $config): void
    {
        $failure = null;

        try {
            $this->mergeConfiguration($config);
        } catch (Throwable $throwable) {
            $failure = $throwable;
        }

        self::assertThat($failure, self::logicalOr(self::isNull(), self::isInstanceOf(TypedNodeEnvPlaceholderException::class)));
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

        if ('custom_risk_patterns' === ($path[1] ?? null)) {
            $configuration += ['regex' => '/unserialize/', 'description' => 'Unserializes input.'];
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
        (new ValidateEnvPlaceholdersPass())->process($containerBuilder);

        return $containerBuilder;
    }
}
