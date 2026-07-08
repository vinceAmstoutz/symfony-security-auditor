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
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Extracts every `#[Route(path:, methods:, name:)]` attribute on a method —
 * one entry per stacked attribute, so a verb restricted to a second, stacked
 * route is never invisible to the caller. Positional and named arguments
 * resolve identically: the first unnamed argument is `path`, matching
 * Symfony's own `Route::__construct()` order, the second is `name`.
 */
final readonly class RouteAttributeParser
{
    /**
     * @param array<AttributeGroup> $attributeGroups
     * @param array<string, string> $classConstants  resolved `self`/`static` class-constant string values, keyed by constant name
     *
     * @return list<array{present: bool, path: ?string, methods: list<string>, name: ?string}>
     */
    public function extract(array $attributeGroups, array $classConstants = []): array
    {
        $routeDataList = [];
        foreach ($attributeGroups as $attributeGroup) {
            foreach ($attributeGroup->attrs as $attribute) {
                if (!$this->attributeShortNameMatches($attribute->name->toString(), 'Route')) {
                    continue;
                }

                $routeDataList[] = $this->routeDataFromArgs($attribute->args, $classConstants);
            }
        }

        return [] === $routeDataList
            ? [['present' => false, 'path' => null, 'methods' => [], 'name' => null]]
            : $routeDataList;
    }

    /**
     * @param array<Arg>            $args
     * @param array<string, string> $classConstants
     *
     * @return array{present: bool, path: ?string, methods: list<string>, name: ?string}
     */
    private function routeDataFromArgs(array $args, array $classConstants): array
    {
        $path = null;
        $methods = [];
        $name = null;
        $positionalIndex = 0;
        foreach ($args as $arg) {
            $argName = $this->resolveRouteArgName($arg->name?->toString(), $positionalIndex);
            if (null === $arg->name) {
                ++$positionalIndex;
            }

            $path = $this->routePathFromArg($argName, $arg, $path, $classConstants);
            $methods = $this->routeMethodsFromArg($argName, $arg) ?? $methods;
            $name = $this->routeNameFromArg($argName, $arg, $name);
        }

        return ['present' => true, 'path' => $path, 'methods' => $methods, 'name' => $name];
    }

    /**
     * @param array<string, string> $classConstants
     */
    private function routePathFromArg(?string $argName, Arg $arg, ?string $currentPath, array $classConstants): ?string
    {
        if ('path' !== $argName) {
            return $currentPath;
        }

        return match (true) {
            $arg->value instanceof String_ => $arg->value->value,
            $arg->value instanceof Array_ => $this->stringValuesFromArray($arg->value)[0] ?? $currentPath,
            $arg->value instanceof ClassConstFetch => $this->resolveSelfConstant($arg->value, $classConstants) ?? $currentPath,
            default => $currentPath,
        };
    }

    /**
     * @param array<string, string> $classConstants
     */
    private function resolveSelfConstant(ClassConstFetch $classConstFetch, array $classConstants): ?string
    {
        if (!$classConstFetch->class instanceof Name || !\in_array($classConstFetch->class->toString(), ['self', 'static'], true)) {
            return null;
        }

        if (!$classConstFetch->name instanceof Identifier) {
            return null;
        }

        return $classConstants[$classConstFetch->name->toString()] ?? null;
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

    private function resolveRouteArgName(?string $argName, int $positionalIndex): ?string
    {
        if (null !== $argName) {
            return $argName;
        }

        return match ($positionalIndex) {
            0 => 'path',
            1 => 'name',
            default => null,
        };
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
