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
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
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
        private NodeFinder $nodeFinder = new NodeFinder(),
        private ThisCallReachability $thisCallReachability = new ThisCallReachability(),
        private IsGrantedAttributeParser $isGrantedAttributeParser = new IsGrantedAttributeParser(),
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

        $classes = $this->nodeFinder->findInstanceOf($ast, Class_::class);

        $entries = [];
        foreach ($classes as $class) {
            foreach ($this->entriesForClass($projectFile->relativePath(), $class) as $entry) {
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
    private function entriesForClass(string $filePath, Class_ $class): array
    {
        $classHasIsGranted = $this->isGrantedAttributeParser->hasValueArg($class->attrGroups);
        $classConstants = $this->classConstantStrings($class);
        $classRouteData = $this->routeAttributeParser->extract($class->attrGroups, $classConstants)[0];
        $methodsByName = $this->methodsByName($class);

        $entries = [];
        foreach ($class->getMethods() as $classMethod) {
            if (!$classMethod->isPublic()) {
                continue;
            }

            $accessFlags = [
                'classHasIsGranted' => $classHasIsGranted,
                'methodHasDenyAccess' => $this->methodInvokesDenyAccess($classMethod, $methodsByName),
            ];

            foreach ($this->buildEntries($filePath, $classMethod, $accessFlags, $classRouteData, $classConstants) as $entry) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * @return array<string, ClassMethod>
     */
    private function methodsByName(Class_ $class): array
    {
        $methodsByName = [];
        foreach ($class->getMethods() as $classMethod) {
            $methodsByName[$classMethod->name->toString()] = $classMethod;
        }

        return $methodsByName;
    }

    /**
     * A `path: self::ADMIN_PATH`/`path: static::ADMIN_PATH` argument references
     * a class constant instead of a literal — a common way to centralize a
     * route prefix. Resolving it to its declared string value (when the
     * constant lives on this same class and holds a literal string) lets the
     * renderer match it against `security.yaml` the same way a literal path
     * already would; a constant declared elsewhere, or not a string literal,
     * is left unresolved rather than guessed at.
     *
     * @return array<string, string>
     */
    private function classConstantStrings(Class_ $class): array
    {
        $constants = [];
        foreach ($class->getConstants() as $classConst) {
            foreach ($classConst->consts as $const) {
                if ($const->value instanceof String_) {
                    $constants[$const->name->toString()] = $const->value->value;
                }
            }
        }

        return $constants;
    }

    /**
     * A class-level `#[Route('/admin', name: 'admin_')]` acts as a path and
     * name prefix for every action's own `#[Route]` — Symfony's own attribute
     * route loader concatenates them, so a security.yaml `access_control`
     * rule keyed on the full `/admin/dashboard` path or `admin_dashboard`
     * route name must be matched against the same joined values, not the
     * method's own attribute in isolation.
     *
     * @param array{classHasIsGranted: bool, methodHasDenyAccess: bool}                 $accessFlags
     * @param array{present: bool, path: ?string, methods: list<string>, name: ?string} $classRouteData
     * @param array<string, string>                                                     $classConstants
     *
     * @return list<RouteAccessControl>
     */
    private function buildEntries(string $filePath, ClassMethod $classMethod, array $accessFlags, array $classRouteData, array $classConstants): array
    {
        $methodLevelIsGranted = $this->isGrantedAttributeParser->extractValues($classMethod->attrGroups);
        $methodHasIsGrantedAttribute = $this->isGrantedAttributeParser->hasValueArg($classMethod->attrGroups);

        $entries = [];
        foreach ($this->routeAttributeParser->extract($classMethod->attrGroups, $classConstants) as $routeData) {
            $entries[] = new RouteAccessControl(
                filePath: $filePath,
                methodName: $classMethod->name->toString(),
                routePath: $this->prefixedRoutePath($classRouteData['path'], $routeData['path']),
                routeMethods: $routeData['methods'],
                hasRouteAttribute: $routeData['present'],
                methodLevelIsGranted: $methodLevelIsGranted,
                methodHasDenyAccess: $accessFlags['methodHasDenyAccess'],
                classHasIsGranted: $accessFlags['classHasIsGranted'],
                routeName: $this->prefixedRouteName($classRouteData['name'], $routeData['name']),
                methodHasIsGrantedAttribute: $methodHasIsGrantedAttribute,
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
        if ('' !== $methodPath && '/' !== $methodPath) {
            return \sprintf('%s/%s', $trimmedPrefix, ltrim($methodPath, '/'));
        }

        if ('' === $trimmedPrefix) {
            return '/';
        }

        return '/' === $methodPath ? \sprintf('%s/', $trimmedPrefix) : $trimmedPrefix;
    }

    private function prefixedRouteName(?string $classNamePrefix, ?string $methodName): ?string
    {
        if (null === $methodName || null === $classNamePrefix) {
            return $methodName;
        }

        return $classNamePrefix.$methodName;
    }

    /**
     * A `denyAccessUnlessGranted()` call moved behind a shared private/protected
     * helper (a common refactor for a repeated check) would otherwise be
     * invisible, since the action method's own body only calls the helper,
     * never `denyAccessUnlessGranted()` directly.
     *
     * @param array<string, ClassMethod> $methodsByName
     */
    private function methodInvokesDenyAccess(ClassMethod $classMethod, array $methodsByName): bool
    {
        $body = $this->thisCallReachability->reachableBody($classMethod, $methodsByName);
        $methodCalls = [
            ...$this->nodeFinder->findInstanceOf($body, MethodCall::class),
            ...$this->nodeFinder->findInstanceOf($body, NullsafeMethodCall::class),
        ];

        foreach ($methodCalls as $methodCall) {
            if ($this->isDenyAccessCall($methodCall)) {
                return true;
            }
        }

        return false;
    }

    /**
     * `isGranted()` is recognized the same way `denyAccessUnlessGranted()`
     * is — by presence alone, not by verifying it actually guards a
     * `throw` — matching this parser's existing heuristic style (the class-
     * level `#[IsGranted]` attribute check applies the identical "presence
     * is sufficient" rule). `isGranted()` + a manual
     * `throw $this->createAccessDeniedException(...)` is an equally standard
     * Symfony idiom to the shorthand `denyAccessUnlessGranted()`, used
     * whenever the action wants a custom denial message.
     */
    private function isDenyAccessCall(MethodCall|NullsafeMethodCall $methodCall): bool
    {
        if ($methodCall->isFirstClassCallable()) {
            return false;
        }

        return $methodCall->name instanceof Identifier
            && \in_array($methodCall->name->toString(), ['denyAccessUnlessGranted', 'isGranted'], true);
    }
}
