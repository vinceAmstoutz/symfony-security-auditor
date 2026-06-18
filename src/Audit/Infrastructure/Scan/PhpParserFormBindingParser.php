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
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\MethodCall;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\FormBindingParserInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Walks each public controller method body looking for
 * `$this->createForm(SomeFormType::class)` call sites. Only literal
 * `FooType::class` arguments are recorded — dynamic class names (variables,
 * method calls returning class strings) are intentionally ignored because the
 * binding cannot be resolved statically.
 */
final readonly class PhpParserFormBindingParser implements FormBindingParserInterface
{
    public function parse(ProjectFile $projectFile): array
    {
        if (ProjectFileType::CONTROLLER !== $projectFile->fileType()) {
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
     * @return array<\PhpParser\Node>|null
     */
    private function parseAndResolveNames(string $content): ?array
    {
        try {
            $parserFactory = new ParserFactory();
            $parser = $parserFactory->createForNewestSupportedVersion();
            $ast = $parser->parse($content);

            if (null === $ast) {
                return null;
            }

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
        $bindings = [];
        foreach ($class->getMethods() as $methodNode) {
            if (!$methodNode->isPublic()) {
                continue;
            }

            $bindings = [...$bindings, ...$this->bindingsForMethod($filePath, $methodNode, $nodeFinder)];
        }

        return $bindings;
    }

    /**
     * @return list<FormBinding>
     */
    private function bindingsForMethod(string $filePath, ClassMethod $classMethod, NodeFinder $nodeFinder): array
    {
        $body = $classMethod->stmts;
        if (null === $body) {
            return [];
        }

        $bindings = [];
        $methodCalls = $nodeFinder->findInstanceOf($body, MethodCall::class);
        foreach ($methodCalls as $methodCall) {
            if (!$this->isThisCreateFormCall($methodCall)) {
                continue;
            }

            $formClass = $this->resolveFirstArgumentClassName($methodCall);
            if (null === $formClass) {
                continue;
            }

            $bindings[] = new FormBinding($filePath, $classMethod->name->toString(), $formClass);
        }

        return $bindings;
    }

    private function isThisCreateFormCall(MethodCall $methodCall): bool
    {
        if (!$methodCall->name instanceof Identifier) {
            return false;
        }

        if ('createForm' !== $methodCall->name->toString()) {
            return false;
        }

        return $methodCall->var instanceof Variable && 'this' === $methodCall->var->name;
    }

    private function resolveFirstArgumentClassName(MethodCall $methodCall): ?string
    {
        $firstArgument = $methodCall->args[0] ?? null;
        if (!$firstArgument instanceof Arg) {
            return null;
        }

        $value = $firstArgument->value;
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
}
