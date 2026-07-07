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
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Attribute;
use PhpParser\Node\AttributeGroup;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ControllerAccessControlParserInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Walks a controller-like file's AST to extract one RouteAccessControl per
 * stacked `#[Route(path:, methods:)]` attribute on each public action method
 * (via {@see RouteAttributeParser}), plus `#[IsGranted(...)]`/`#[Security(...)]`
 * on both class and method level and `denyAccessUnlessGranted()` calls in
 * method bodies (a first-class callable reference to it does not count — it
 * is never actually invoked). Attribute names are resolved against their
 * imports (`NameResolver`) before short-name matching, so an aliased import
 * (`use Route as Get;`) is still recognised. "Controller-like" also covers
 * `#[AsLiveComponent]`/`#[ApiResource]` classes ({@see
 * ProjectFileType::isControllerLike()}), which may still declare routed,
 * access-controlled actions. Returns [] for any other file type or any parse
 * error — the mapping stage must never abort because of a single broken file.
 */
final readonly class PhpParserControllerAccessControlParser implements ControllerAccessControlParserInterface
{
    public function __construct(
        private RouteAttributeParser $routeAttributeParser = new RouteAttributeParser(),
    ) {}

    #[Override]
    public function parse(ProjectFile $projectFile): array
    {
        if (!$projectFile->fileType()->isControllerLike()) {
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
     * @return array<Node>|null
     */
    private function parseToAst(string $content): ?array
    {
        try {
            $parserFactory = new ParserFactory();
            $parser = $parserFactory->createForNewestSupportedVersion();
            $ast = $parser->parse($content) ?? [];

            $nodeTraverser = new NodeTraverser();
            $nodeTraverser->addVisitor(new NameResolver());

            return $nodeTraverser->traverse($ast);
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
        $classRouteData = $this->routeAttributeParser->extract($class->attrGroups)[0];

        $entries = [];
        foreach ($class->getMethods() as $classMethod) {
            if (!$classMethod->isPublic()) {
                continue;
            }

            foreach ($this->buildEntries($filePath, $classMethod, $classHasIsGranted, $classRouteData, $nodeFinder) as $entry) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * A class-level `#[Route('/admin', name: 'admin_')]` acts as a path and
     * name prefix for every action's own `#[Route]` — Symfony's own attribute
     * route loader concatenates them, so a security.yaml `access_control`
     * rule keyed on the full `/admin/dashboard` path or `admin_dashboard`
     * route name must be matched against the same joined values, not the
     * method's own attribute in isolation.
     *
     * @param array{present: bool, path: ?string, methods: list<string>, name: ?string} $classRouteData
     *
     * @return list<RouteAccessControl>
     */
    private function buildEntries(string $filePath, ClassMethod $classMethod, bool $classHasIsGranted, array $classRouteData, NodeFinder $nodeFinder): array
    {
        $methodLevelIsGranted = $this->extractIsGrantedValues($classMethod->attrGroups);
        $methodHasDenyAccess = $this->methodInvokesDenyAccess($classMethod, $nodeFinder);

        $entries = [];
        foreach ($this->routeAttributeParser->extract($classMethod->attrGroups) as $routeData) {
            $entries[] = new RouteAccessControl(
                filePath: $filePath,
                methodName: $classMethod->name->toString(),
                routePath: $this->prefixedRoutePath($classRouteData['path'], $routeData['path']),
                routeMethods: $routeData['methods'],
                hasRouteAttribute: $routeData['present'],
                methodLevelIsGranted: $methodLevelIsGranted,
                methodHasDenyAccess: $methodHasDenyAccess,
                classHasIsGranted: $classHasIsGranted,
                routeName: $this->prefixedRouteName($classRouteData['name'], $routeData['name']),
            );
        }

        return $entries;
    }

    private function prefixedRoutePath(?string $classPathPrefix, ?string $methodPath): ?string
    {
        if (null === $methodPath || null === $classPathPrefix) {
            return $methodPath;
        }

        $trimmedPrefix = rtrim($classPathPrefix, '/');
        if ('' === $methodPath || '/' === $methodPath) {
            return '' === $trimmedPrefix ? '/' : $trimmedPrefix;
        }

        return \sprintf('%s/%s', $trimmedPrefix, ltrim($methodPath, '/'));
    }

    private function prefixedRouteName(?string $classNamePrefix, ?string $methodName): ?string
    {
        if (null === $methodName || null === $classNamePrefix) {
            return $methodName;
        }

        return $classNamePrefix.$methodName;
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
            $valueArgName = $this->valueArgNameFor($attribute->name->toString());
            if (null === $valueArgName) {
                continue;
            }

            $attributeArg = $this->isGrantedAttributeArgValue($attribute->args, $valueArgName);
            if (null !== $attributeArg) {
                $values[] = $attributeArg;
            }
        }

        return $values;
    }

    /**
     * `#[IsGranted]`'s first parameter is `$attribute`; `#[Security]`'s is
     * `$expression` — resolve whichever applies the same way
     * `resolveRouteArgName()` resolves `Route`'s `path`, so a reordered
     * named-argument call (e.g. `#[IsGranted(subject: $post, attribute:
     * 'EDIT')]`) still yields the attribute, not whichever string argument
     * happens to come first.
     */
    private function valueArgNameFor(string $shortName): ?string
    {
        return match (true) {
            $this->attributeShortNameMatches($shortName, 'IsGranted') => 'attribute',
            $this->attributeShortNameMatches($shortName, 'Security') => 'expression',
            default => null,
        };
    }

    /**
     * @param list<Arg> $args
     */
    private function isGrantedAttributeArgValue(array $args, string $valueArgName): ?string
    {
        foreach ($args as $index => $arg) {
            if (!$arg->value instanceof String_) {
                continue;
            }

            if ($this->isIsGrantedAttributeArg($arg, $index, $valueArgName)) {
                return $arg->value->value;
            }
        }

        return null;
    }

    private function isIsGrantedAttributeArg(Arg $arg, int $index, string $valueArgName): bool
    {
        return match (true) {
            $arg->name instanceof Identifier => $valueArgName === $arg->name->toString(),
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
            if ($methodCall->isFirstClassCallable()) {
                continue;
            }

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
}
