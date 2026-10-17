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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Configuration;

use BackedEnum;
use LogicException;
use Symfony\Component\Config\Definition\BaseNode;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\Compiler\MergeExtensionConfigurationPass;
use Symfony\Component\DependencyInjection\Compiler\ValidateEnvPlaceholdersPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ParameterBag\EnvPlaceholderParameterBag;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;

/**
 * What the configuration takes at one path: which of a fixed set of values
 * the bundle loads with — the tree accepts it and the extension builds its
 * services from it, so a value the tree let through but the release then
 * failed on is not counted as taken — and what each becomes once processed,
 * whether a kernel takes an `%env()%` placeholder there, and the container
 * parameters the bundle publishes for its default configuration and for each
 * profile.
 */
final readonly class ConfigurationProbe
{
    public const array VALUES = [
        'true' => true,
        'false' => false,
        'zero' => 0,
        'one' => 1,
        'minus-one' => -1,
        'hundred-and-one' => 101,
        'one-and-a-half' => 1.5,
        'zero-float' => 0.0,
        'text' => 'abc',
        'empty-text' => '',
        'numeric-text' => '5',
        'severity' => 'high',
        'format' => 'json',
        'null' => null,
        'empty-list' => [],
        'list' => ['a'],
    ];

    private const string PARAMETER_PREFIX = 'symfony_security_auditor.';

    private const string PLACEHOLDER = '%env(SSA_PROBE)%';

    /**
     * @param array<string, NodeInterface> $nodes
     *
     * @return array<string, array{accepted: bool, value?: mixed}>
     */
    public static function values(array $nodes, string $path): array
    {
        $outcomes = [];
        foreach (self::VALUES as $name => $value) {
            $outcomes[$name] = self::processed($nodes, $path, $value);
        }

        return $outcomes;
    }

    /**
     * @param array<string, NodeInterface> $nodes
     */
    public static function takesEnvironmentPlaceholder(array $nodes, string $path): bool
    {
        [$configuration] = ProbeConfiguration::holding($nodes, $path, self::PLACEHOLDER);

        try {
            (new ValidateEnvPlaceholdersPass())->process(self::merged($configuration));
        } catch (Throwable) {
            return false;
        } finally {
            BaseNode::resetPlaceholders();
        }

        return true;
    }

    /**
     * @return array<string, mixed> the parameters of the default configuration, or of the one that only selects this profile
     */
    public static function parameters(?string $profile = null): array
    {
        $parameters = [];
        foreach (self::merged(['model' => 'gpt-4o', ...(null === $profile ? [] : ['profile' => $profile])])->getParameterBag()->all() as $name => $value) {
            if (\is_string($name) && str_starts_with($name, self::PARAMETER_PREFIX)) {
                $parameters[$name] = self::exportable($value);
            }
        }

        BaseNode::resetPlaceholders();
        ksort($parameters);

        return $parameters;
    }

    /**
     * @param array<string, NodeInterface> $nodes
     *
     * @return array{accepted: bool, value?: mixed}
     */
    private static function processed(array $nodes, string $path, mixed $value): array
    {
        [$configuration, $readPath] = ProbeConfiguration::holding($nodes, $path, $value);

        try {
            $processed = (new Processor())->processConfiguration(ConfigurationTree::configuration(), [$configuration]);
            self::merged($configuration);
        } catch (Throwable) {
            return ['accepted' => false];
        }

        return ['accepted' => true, 'value' => self::exportable(self::read($processed, $readPath))];
    }

    /**
     * @param list<int|string> $readPath
     */
    private static function read(mixed $processed, array $readPath): mixed
    {
        foreach ($readPath as $key) {
            $processed = \is_array($processed) && \array_key_exists($key, $processed) ? $processed[$key] : '<absent>';
        }

        return $processed;
    }

    /**
     * @param array<array-key, mixed> $configuration
     */
    private static function merged(array $configuration): ContainerBuilder
    {
        $containerBuilder = new ContainerBuilder(new EnvPlaceholderParameterBag([
            'kernel.cache_dir' => '/tmp/ssa-cache',
            'kernel.build_dir' => '/tmp/ssa-cache',
            'kernel.project_dir' => '/tmp/ssa-project',
            'kernel.environment' => 'prod',
            'kernel.debug' => false,
        ]));
        $extension = (new SymfonySecurityAuditorBundle())->getContainerExtension() ?? throw new LogicException('The bundle has no extension.');
        $containerBuilder->registerExtension($extension);
        $containerBuilder->loadFromExtension('symfony_security_auditor', array_filter($configuration, \is_string(...), \ARRAY_FILTER_USE_KEY));
        (new MergeExtensionConfigurationPass())->process($containerBuilder);

        return $containerBuilder;
    }

    private static function exportable(mixed $value): mixed
    {
        return match (true) {
            $value instanceof BackedEnum => $value->value,
            \is_array($value) => array_map(self::exportable(...), $value),
            \is_object($value) => $value::class,
            \is_float($value) => round($value, 9),
            default => $value,
        };
    }
}
