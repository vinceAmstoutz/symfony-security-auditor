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
use ReflectionProperty;
use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\BooleanNode;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\EnumNode;
use Symfony\Component\Config\Definition\FloatNode;
use Symfony\Component\Config\Definition\IntegerNode;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\NumericNode;
use Symfony\Component\Config\Definition\PrototypedArrayNode;
use Symfony\Component\Config\Definition\ScalarNode;
use Symfony\Component\Config\Definition\VariableNode;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ConfigurationExtensionInterface;
use UnitEnum;
use VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle;

/**
 * The bundle's configuration tree, path by path: `audit.max_iterations`, a
 * prototype's entries as `audit.excluded_types.*`, each described by its
 * kind, its default, its choices, its bounds and whether it is required.
 */
final readonly class ConfigurationTree
{
    public const string ENTRY = '*';

    private const array KINDS = [
        BooleanNode::class => 'boolean',
        EnumNode::class => 'enum',
        IntegerNode::class => 'integer',
        FloatNode::class => 'float',
        ScalarNode::class => 'scalar',
        PrototypedArrayNode::class => 'prototype',
        ArrayNode::class => 'array',
        VariableNode::class => 'variable',
    ];

    public static function configuration(): ConfigurationInterface
    {
        $extension = (new SymfonySecurityAuditorBundle())->getContainerExtension();
        $configuration = $extension instanceof ConfigurationExtensionInterface ? $extension->getConfiguration([], new ContainerBuilder()) : null;
        if (!$configuration instanceof ConfigurationInterface) {
            throw new LogicException('The bundle exposes no configuration.');
        }

        return $configuration;
    }

    /**
     * @return array<string, NodeInterface> every node below the root, by path
     */
    public static function nodes(): array
    {
        $node = self::configuration()->getConfigTreeBuilder()->buildTree();

        return $node instanceof ArrayNode ? self::nodesUnder($node, '') : [];
    }

    /**
     * @return array<string, mixed>
     */
    public static function describe(NodeInterface $node): array
    {
        return [
            'kind' => self::kind($node),
            'required' => $node->isRequired(),
            'default' => $node instanceof ArrayNode && !$node instanceof PrototypedArrayNode ? null : self::defaultOf($node),
            'values' => $node instanceof EnumNode ? array_map(self::choice(...), $node->getValues()) : null,
            'min' => $node instanceof NumericNode ? self::bound($node, 'min') : null,
            'max' => $node instanceof NumericNode ? self::bound($node, 'max') : null,
        ];
    }

    public static function kind(NodeInterface $node): string
    {
        foreach (self::KINDS as $class => $kind) {
            if ($node instanceof $class) {
                return $kind;
            }
        }

        return $node::class;
    }

    /**
     * @return array<string, NodeInterface>
     */
    private static function nodesUnder(ArrayNode $arrayNode, string $prefix): array
    {
        $nodes = [];
        $children = $arrayNode instanceof PrototypedArrayNode ? [self::ENTRY => $arrayNode->getPrototype()] : $arrayNode->getChildren();

        foreach ($children as $name => $child) {
            $path = '' === $prefix ? $name : \sprintf('%s.%s', $prefix, $name);
            $nodes[$path] = $child;
            if ($child instanceof ArrayNode) {
                $nodes = [...$nodes, ...self::nodesUnder($child, $path)];
            }
        }

        return $nodes;
    }

    private static function defaultOf(NodeInterface $node): mixed
    {
        return $node->hasDefaultValue() ? ['value' => self::exportable($node->getDefaultValue())] : 'none';
    }

    private static function bound(NumericNode $numericNode, string $bound): int|float|null
    {
        $value = (new ReflectionProperty(NumericNode::class, $bound))->getValue($numericNode);

        return \is_int($value) || \is_float($value) ? $value : null;
    }

    private static function choice(mixed $value): mixed
    {
        return $value instanceof BackedEnum ? $value->value : self::exportable($value);
    }

    private static function exportable(mixed $value): mixed
    {
        return match (true) {
            $value instanceof BackedEnum => $value->value,
            $value instanceof UnitEnum => $value->name,
            \is_array($value) => array_map(self::exportable(...), $value),
            \is_object($value) => $value::class,
            default => $value,
        };
    }
}
