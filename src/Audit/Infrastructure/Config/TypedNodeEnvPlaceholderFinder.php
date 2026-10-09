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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\BooleanNode;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\NumericNode;
use Symfony\Component\Config\Definition\PrototypedArrayNode;
use Symfony\Component\Config\Definition\ScalarNode;
use Symfony\Component\DependencyInjection\ParameterBag\EnvPlaceholderParameterBag;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

/**
 * Symfony's configuration tree lets a `%env()%` placeholder through any node
 * and leaves it to the extension to cope. The bundle builds typed value
 * objects while the container is built, before a variable has a value, so a
 * placeholder on a number, a switch, a list or a choice (read as a PHP enum
 * or checked against a fixed list of values) can only crash it. This finder
 * names those settings; a free-text setting keeps its placeholder for the
 * container to resolve where the text is used.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class TypedNodeEnvPlaceholderFinder
{
    private const string ROOT = 'symfony_security_auditor';

    /**
     * @param array<array-key, mixed> $config the processed bundle configuration
     *
     * @return list<string> the dotted path of every setting that holds a placeholder it cannot take
     */
    public function pathsIn(array $config, ParameterBagInterface $parameterBag): array
    {
        if (!$parameterBag instanceof EnvPlaceholderParameterBag) {
            return [];
        }

        return $this->placeholderPaths($config, $this->configurationTree(), self::ROOT, $parameterBag->getEnvPlaceholderUniquePrefix());
    }

    private function configurationTree(): NodeInterface
    {
        $treeBuilder = new TreeBuilder(self::ROOT);
        (new AuditConfigurationDefinition())->defineChildren($treeBuilder->getRootNode()->children());

        return $treeBuilder->buildTree();
    }

    /**
     * @return list<string>
     */
    private function placeholderPaths(mixed $value, NodeInterface $node, string $path, string $prefix): array
    {
        if (\is_string($value)) {
            return $this->refusesPlaceholder($node) && str_starts_with($value, $prefix) ? [$path] : [];
        }

        if (!\is_array($value)) {
            return [];
        }

        return match (true) {
            $node instanceof PrototypedArrayNode => $this->prototypedPlaceholderPaths($value, $node, $path, $prefix),
            $node instanceof ArrayNode => $this->declaredPlaceholderPaths($value, $node, $path, $prefix),
            default => [],
        };
    }

    /**
     * @param array<array-key, mixed> $values
     *
     * @return list<string>
     */
    private function prototypedPlaceholderPaths(array $values, PrototypedArrayNode $prototypedArrayNode, string $path, string $prefix): array
    {
        $paths = [];

        foreach ($values as $key => $value) {
            $paths = [...$paths, ...$this->placeholderPaths($value, $prototypedArrayNode->getPrototype(), \sprintf('%s.%s', $path, $key), $prefix)];
        }

        return $paths;
    }

    /**
     * @param array<array-key, mixed> $values
     *
     * @return list<string>
     */
    private function declaredPlaceholderPaths(array $values, ArrayNode $arrayNode, string $path, string $prefix): array
    {
        $paths = [];

        foreach ($arrayNode->getChildren() as $name => $node) {
            if (\array_key_exists($name, $values)) {
                $paths = [...$paths, ...$this->placeholderPaths($values[$name], $node, \sprintf('%s.%s', $path, $name), $prefix)];
            }
        }

        return $paths;
    }

    private function refusesPlaceholder(NodeInterface $node): bool
    {
        return !$node instanceof ScalarNode
            || $node instanceof NumericNode
            || $node instanceof BooleanNode
            || true === $node->getAttribute(AuditConfigurationDefinition::REFUSES_ENV_PLACEHOLDER);
    }
}
