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
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\FormBindingParserInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Walks each public controller-like method body looking for
 * `$this->createForm(SomeFormType::class)` (or `self::`/`static::createForm(...)`)
 * call sites, following calls into same-class helper methods via {@see
 * ThisCallReachability} so a call moved behind a shared private/protected
 * helper is still attributed to the public action that reaches it. Only
 * literal `FooType::class` arguments are recorded — dynamic class names
 * (variables, method calls returning class strings) are intentionally ignored
 * because the binding cannot be resolved statically. "Controller-like" also
 * covers `#[AsLiveComponent]`/`#[ApiResource]` classes that also extend
 * `AbstractController`.
 */
final readonly class PhpParserFormBindingParser implements FormBindingParserInterface
{
    public function __construct(
        private ThisCallReachability $thisCallReachability = new ThisCallReachability(),
    ) {}

    #[Override]
    public function parse(ProjectFile $projectFile): array
    {
        if (!$projectFile->fileType()->isControllerLike()) {
            return [];
        }

        $ast = $this->parseAndResolveNames($projectFile->content());
        if (null === $ast) {
            return [];
        }

        $nodeFinder = new NodeFinder();
        $classes = $nodeFinder->findInstanceOf($ast, Class_::class);

        return $this->bindingsForClasses($projectFile->relativePath(), $classes, $nodeFinder);
    }

    /**
     * @return array<Node>|null
     */
    private function parseAndResolveNames(string $content): ?array
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
     * @param array<Class_> $classes
     *
     * @return list<FormBinding>
     */
    private function bindingsForClasses(string $filePath, array $classes, NodeFinder $nodeFinder): array
    {
        $bindings = [];
        foreach ($classes as $class) {
            $bindings = [...$bindings, ...$this->bindingsForPublicMethods($filePath, $class, $nodeFinder)];
        }

        return $bindings;
    }

    /**
     * @return list<FormBinding>
     */
    private function bindingsForPublicMethods(string $filePath, Class_ $class, NodeFinder $nodeFinder): array
    {
        $methodsByName = $this->methodsByName($class);

        $bindings = [];
        foreach ($class->getMethods() as $classMethod) {
            if (!$classMethod->isPublic()) {
                continue;
            }

            $bindings = [...$bindings, ...$this->bindingsForMethod($filePath, $classMethod, $methodsByName, $nodeFinder)];
        }

        return $bindings;
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
     * @param array<string, ClassMethod> $methodsByName
     *
     * @return list<FormBinding>
     */
    private function bindingsForMethod(string $filePath, ClassMethod $classMethod, array $methodsByName, NodeFinder $nodeFinder): array
    {
        $body = $this->thisCallReachability->reachableBody($classMethod, $methodsByName);

        $bindings = [];
        foreach ($this->createFormCallSites($body, $nodeFinder) as $call) {
            if (!$this->isCreateFormCall($call)) {
                continue;
            }

            $formClass = $this->resolveFirstArgumentClassName($call);
            if (null === $formClass) {
                continue;
            }

            $bindings[] = new FormBinding($filePath, $classMethod->name->toString(), $formClass);
        }

        return $bindings;
    }

    /**
     * Deduplicates by node identity: a diamond-shaped helper call graph (two
     * reachable methods both calling a shared third helper) can otherwise
     * surface the same call site twice via {@see ThisCallReachability}.
     *
     * @param array<Node> $body
     *
     * @return list<MethodCall|NullsafeMethodCall|StaticCall>
     */
    private function createFormCallSites(array $body, NodeFinder $nodeFinder): array
    {
        $callsBySpotId = [];
        foreach ([
            ...$nodeFinder->findInstanceOf($body, MethodCall::class),
            ...$nodeFinder->findInstanceOf($body, NullsafeMethodCall::class),
            ...$nodeFinder->findInstanceOf($body, StaticCall::class),
        ] as $call) {
            $callsBySpotId[spl_object_id($call)] = $call;
        }

        $calls = $callsBySpotId;
        usort($calls, static fn (MethodCall|NullsafeMethodCall|StaticCall $a, MethodCall|NullsafeMethodCall|StaticCall $b): int => $a->getStartTokenPos() <=> $b->getStartTokenPos());

        return $calls;
    }

    private function isCreateFormCall(MethodCall|NullsafeMethodCall|StaticCall $call): bool
    {
        if (!$call->name instanceof Identifier || 'createForm' !== $call->name->toString()) {
            return false;
        }

        if ($call instanceof StaticCall) {
            return $call->class instanceof Name && \in_array($call->class->toString(), ['self', 'static'], true);
        }

        return $call->var instanceof Variable && 'this' === $call->var->name;
    }

    private function resolveFirstArgumentClassName(MethodCall|NullsafeMethodCall|StaticCall $call): ?string
    {
        $typeArgument = $this->typeArgument(array_values($call->args));
        if (!$typeArgument instanceof Arg) {
            return null;
        }

        $value = $typeArgument->value;
        if (!$value instanceof ClassConstFetch) {
            return null;
        }

        if (!$value->name instanceof Identifier) {
            return null;
        }

        if ('class' !== $value->name->toString()) {
            return null;
        }

        if (!$value->class instanceof Name) {
            return null;
        }

        return $value->class->toString();
    }

    /**
     * `createForm(string $type, mixed $data = null, array $options = [])`'s
     * `$type` is conventionally the first positional argument, but a caller
     * may name every argument and reorder them (e.g. `createForm(data: ...,
     * type: ...)`) — resolve `type` the same way `Route`'s `path` and
     * `IsGranted`'s `attribute` are resolved elsewhere in this scanner.
     *
     * @param list<Arg|Node\VariadicPlaceholder> $args
     */
    private function typeArgument(array $args): ?Arg
    {
        foreach ($args as $index => $arg) {
            if ($arg instanceof Arg && $this->isTypeArg($arg, $index)) {
                return $arg;
            }
        }

        return null;
    }

    private function isTypeArg(Arg $arg, int $index): bool
    {
        return match (true) {
            $arg->name instanceof Identifier => 'type' === $arg->name->toString(),
            default => 0 === $index,
        };
    }
}
