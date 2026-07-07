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

use Override;
use PhpParser\Node\Arg;
use PhpParser\Node\Attribute;
use PhpParser\Node\AttributeGroup;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ControllerAccessControlParserInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Walks a controller's AST to extract one RouteAccessControl per public action
 * method. Recognises `#[Route(path:, methods:)]` on methods, `#[IsGranted(...)]`
 * on both class and method level (matched by short name to survive aliased
 * imports), and `denyAccessUnlessGranted()` calls in method bodies. Returns
 * [] for any non-controller file or any parse error — the mapping stage must
 * never abort because of a single broken file.
 */
final readonly class PhpParserControllerAccessControlParser implements ControllerAccessControlParserInterface
{
    #[Override]
    public function parse(ProjectFile $projectFile): array
    {
        if (ProjectFileType::CONTROLLER !== $projectFile->fileType()) {
            return [];
        }

        $ast = $this->parseToAst($projectFile->content());
        if (null === $ast) {
            return [];
        }

        $nodeFinder = new NodeFinder();
        $classes = $nodeFinder->findInstanceOf($ast, Class_::class);

        $entries = [];
        foreach ($classes as $class) {
            foreach ($this->entriesForClass($projectFile->relativePath(), $class, $nodeFinder) as $entry) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * @return Stmt[]|null
     */
    private function parseToAst(string $content): ?array
    {
        try {
            $parserFactory = new ParserFactory();
            $parser = $parserFactory->createForNewestSupportedVersion();

            return $parser->parse($content);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @return list<RouteAccessControl>
     */
    private function entriesForClass(string $filePath, Class_ $class, NodeFinder $nodeFinder): array
    {
        $classHasIsGranted = $this->hasIsGrantedAttribute($class->attrGroups);

        $entries = [];
        foreach ($class->getMethods() as $classMethod) {
            if (!$classMethod->isPublic()) {
                continue;
            }

            $entries[] = $this->buildEntry($filePath, $classMethod, $classHasIsGranted, $nodeFinder);
        }

        return $entries;
    }

    private function buildEntry(string $filePath, ClassMethod $classMethod, bool $classHasIsGranted, NodeFinder $nodeFinder): RouteAccessControl
    {
        $routeData = $this->extractRouteAttribute($classMethod->attrGroups);
        $methodLevelIsGranted = $this->extractIsGrantedValues($classMethod->attrGroups);
        $methodHasDenyAccess = $this->methodInvokesDenyAccess($classMethod, $nodeFinder);

        return new RouteAccessControl(
            filePath: $filePath,
            methodName: $classMethod->name->toString(),
            routePath: $routeData['path'],
            routeMethods: $routeData['methods'],
            hasRouteAttribute: $routeData['present'],
            methodLevelIsGranted: $methodLevelIsGranted,
            methodHasDenyAccess: $methodHasDenyAccess,
            classHasIsGranted: $classHasIsGranted,
            routeName: $routeData['name'],
        );
    }

    /**
     * @param array<AttributeGroup> $attributeGroups
     *
     * @return array{present: bool, path: ?string, methods: list<string>, name: ?string}
     */
    private function extractRouteAttribute(array $attributeGroups): array
    {
        foreach ($attributeGroups as $attributeGroup) {
            foreach ($attributeGroup->attrs as $attribute) {
                if (!$this->attributeShortNameMatches($attribute->name->toString(), 'Route')) {
                    continue;
                }

                return $this->routeDataFromArgs($attribute->args);
            }
        }

        return ['present' => false, 'path' => null, 'methods' => [], 'name' => null];
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

    /**
     * @param array<AttributeGroup> $attributeGroups
     *
     * @return list<string>
     */
    private function extractIsGrantedValues(array $attributeGroups): array
    {
        $values = [];
        foreach ($attributeGroups as $attributeGroup) {
            foreach ($this->isGrantedValuesFromAttributes($attributeGroup->attrs) as $value) {
                $values[] = $value;
            }
        }

        return $values;
    }

    /**
     * @param array<Attribute> $attributes
     *
     * @return list<string>
     */
    private function isGrantedValuesFromAttributes(array $attributes): array
    {
        $values = [];
        foreach ($attributes as $attribute) {
            if (!$this->attributeShortNameMatches($attribute->name->toString(), 'IsGranted')) {
                continue;
            }

            $attributeArg = $this->isGrantedAttributeArgValue($attribute->args);
            if (null !== $attributeArg) {
                $values[] = $attributeArg;
            }
        }

        return $values;
    }

    /**
     * `#[IsGranted]`'s first parameter is `$attribute` — resolve it the same
     * way `resolveRouteArgName()` resolves `Route`'s `path`, so a reordered
     * named-argument call (e.g. `#[IsGranted(subject: $post, attribute:
     * 'EDIT')]`) still yields the attribute, not whichever string argument
     * happens to come first.
     *
     * @param list<Arg> $args
     */
    private function isGrantedAttributeArgValue(array $args): ?string
    {
        foreach ($args as $index => $arg) {
            if (!$arg->value instanceof String_) {
                continue;
            }

            if ($this->isIsGrantedAttributeArg($arg, $index)) {
                return $arg->value->value;
            }
        }

        return null;
    }

    private function isIsGrantedAttributeArg(Arg $arg, int $index): bool
    {
        return match (true) {
            $arg->name instanceof Identifier => 'attribute' === $arg->name->toString(),
            default => 0 === $index,
        };
    }

    /**
     * @param array<AttributeGroup> $attributeGroups
     */
    private function hasIsGrantedAttribute(array $attributeGroups): bool
    {
        return [] !== $this->extractIsGrantedValues($attributeGroups);
    }

    private function methodInvokesDenyAccess(ClassMethod $classMethod, NodeFinder $nodeFinder): bool
    {
        $methodCalls = $nodeFinder->findInstanceOf($classMethod->stmts ?? [], MethodCall::class);
        foreach ($methodCalls as $methodCall) {
            if ($methodCall->name instanceof Identifier && 'denyAccessUnlessGranted' === $methodCall->name->toString()) {
                return true;
            }
        }

        return false;
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
