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

use ReflectionProperty;
use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\EnumNode;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\PrototypedArrayNode;

/**
 * The smallest configuration that sets one path to a value: the model the
 * bundle requires, the required siblings of every section on the way, and a
 * prototype's entry as the first item of a list, or the `controller` item of
 * a map keyed by name: a file type, so a map keyed by file type, such as
 * `scan.custom_risk_patterns`, takes it as well as one keyed by any name.
 */
final readonly class ProbeConfiguration
{
    private const string MODEL = 'gpt-4o';

    private const string KEYED_ENTRY = 'controller';

    /**
     * @param array<string, NodeInterface> $nodes
     *
     * @return array{array<array-key, mixed>, list<int|string>} the configuration, and where the value lands once processed
     */
    public static function holding(array $nodes, string $path, mixed $value): array
    {
        $segments = explode('.', $path);
        [$configuration, $readPath] = self::nest($nodes, $segments, '', $value);

        return [['model' => self::MODEL, ...(\is_array($configuration) ? $configuration : [])], $readPath];
    }

    public static function sample(NodeInterface $node): mixed
    {
        return match (ConfigurationTree::kind($node)) {
            'enum' => $node instanceof EnumNode ? $node->getValues()[0] : null,
            'boolean' => false,
            'integer' => 1,
            'float' => 1.0,
            'prototype' => [],
            'array' => $node instanceof ArrayNode ? self::requiredChildren($node) : [],
            default => 'probe',
        };
    }

    /**
     * @param array<string, NodeInterface> $nodes
     * @param list<string>                 $segments
     *
     * @return array{mixed, list<int|string>}
     */
    private static function nest(array $nodes, array $segments, string $prefix, mixed $value): array
    {
        if ([] === $segments) {
            return [$value, []];
        }

        $segment = array_shift($segments);
        $path = '' === $prefix ? $segment : \sprintf('%s.%s', $prefix, $segment);
        [$inner, $readPath] = self::nest($nodes, $segments, $path, $value);
        $parent = '' === $prefix ? null : $nodes[$prefix] ?? null;

        if (ConfigurationTree::ENTRY === $segment && $parent instanceof PrototypedArrayNode) {
            $entry = self::withRequiredChildren($nodes[$path] ?? null, $inner);
            $key = self::isKeyedByName($parent) ? self::KEYED_ENTRY : 0;

            return [[$key => $entry], [$key, ...$readPath]];
        }

        return [[$segment => $inner], [$segment, ...$readPath]];
    }

    private static function withRequiredChildren(?NodeInterface $node, mixed $inner): mixed
    {
        if (!$node instanceof ArrayNode || !\is_array($inner)) {
            return $inner;
        }

        return [...self::requiredChildren($node), ...$inner];
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function requiredChildren(ArrayNode $arrayNode): array
    {
        $required = [];
        foreach ($arrayNode->getChildren() as $name => $node) {
            if ($node->isRequired()) {
                $required[$name] = self::sample($node);
            }
        }

        return $required;
    }

    private static function isKeyedByName(PrototypedArrayNode $prototypedArrayNode): bool
    {
        return null !== (new ReflectionProperty(PrototypedArrayNode::class, 'keyAttribute'))->getValue($prototypedArrayNode);
    }
}
