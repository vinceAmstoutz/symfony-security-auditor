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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use PhpParser\Node\Arg;
use PhpParser\Node\AttributeGroup;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\String_;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Extracts every `#[Route(path:, methods:, name:)]` attribute on a method —
 * one entry per stacked attribute, so a verb restricted to a second, stacked
 * route is never invisible to the caller. Positional and named arguments
 * resolve identically: the first unnamed argument is `path`.
 */
final readonly class RouteAttributeParser
{
    /**
     * @param array<AttributeGroup> $attributeGroups
     *
     * @return list<array{present: bool, path: ?string, methods: list<string>, name: ?string}>
     */
    public function extract(array $attributeGroups): array
    {
        $routeDataList = [];
        foreach ($attributeGroups as $attributeGroup) {
            foreach ($attributeGroup->attrs as $attribute) {
                if (!$this->attributeShortNameMatches($attribute->name->toString(), 'Route')) {
                    continue;
                }

                $routeDataList[] = $this->routeDataFromArgs($attribute->args);
            }
        }

        return [] === $routeDataList
            ? [['present' => false, 'path' => null, 'methods' => [], 'name' => null]]
            : $routeDataList;
    }

    /**
     * @param array<Arg> $args
     *
     * @return array{present: bool, path: ?string, methods: list<string>, name: ?string}
     */
    private function routeDataFromArgs(array $args): array
    {
        $path = null;
        $methods = [];
        $name = null;
        $firstPositionalConsumed = false;
        foreach ($args as $arg) {
            $argName = $this->resolveRouteArgName($arg->name?->toString(), $firstPositionalConsumed);
            $firstPositionalConsumed = $firstPositionalConsumed || null === $arg->name;

            $path = $this->routePathFromArg($argName, $arg, $path);
            $methods = $this->routeMethodsFromArg($argName, $arg) ?? $methods;
            $name = $this->routeNameFromArg($argName, $arg, $name);
        }

        return ['present' => true, 'path' => $path, 'methods' => $methods, 'name' => $name];
    }

    private function routePathFromArg(?string $argName, Arg $arg, ?string $currentPath): ?string
    {
        if ('path' === $argName && $arg->value instanceof String_) {
            return $arg->value->value;
        }

        return $currentPath;
    }

    private function routeNameFromArg(?string $argName, Arg $arg, ?string $currentName): ?string
    {
        if ('name' === $argName && $arg->value instanceof String_) {
            return $arg->value->value;
        }

        return $currentName;
    }

    /**
     * @return list<string>|null
     */
    private function routeMethodsFromArg(?string $argName, Arg $arg): ?array
    {
        return match (true) {
            'methods' !== $argName => null,
            $arg->value instanceof Array_ => $this->stringValuesFromArray($arg->value),
            $arg->value instanceof String_ => [$arg->value->value],
            default => null,
        };
    }

    private function resolveRouteArgName(?string $argName, bool $firstPositionalConsumed): ?string
    {
        if (null === $argName && !$firstPositionalConsumed) {
            return 'path';
        }

        return $argName;
    }

    private function attributeShortNameMatches(string $fullyQualifiedName, string $expectedShortName): bool
    {
        $parts = explode('\\', $fullyQualifiedName);

        return end($parts) === $expectedShortName;
    }

    /**
     * @return list<string>
     */
    private function stringValuesFromArray(Array_ $array): array
    {
        $values = [];
        foreach ($array->items as $item) {
            if ($item->value instanceof String_) {
                $values[] = $item->value->value;
            }
        }

        return $values;
    }
}
