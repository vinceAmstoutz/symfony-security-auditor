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

use Closure;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;

/**
 * Follows `$this->helper()` calls into the methods of the same class, so an
 * AST parser sees a check moved behind a helper. Visits each method once, so
 * mutually calling helpers end.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ThisCallReachability
{
    public function __construct(
        private NodeFinder $nodeFinder = new NodeFinder(),
    ) {}

    /**
     * Every statement reachable from the method, each method's once, in
     * depth-first call order.
     *
     * @param array<string, ClassMethod> $methodsByName
     *
     * @return array<Node>
     */
    public function reachableBody(ClassMethod $classMethod, array $methodsByName): array
    {
        $visited = [];
        $result = [];
        $stack = [$classMethod];

        while ([] !== $stack) {
            $current = array_pop($stack);
            $name = $current->name->toString();
            if (\array_key_exists($name, $visited)) {
                continue;
            }

            $visited[$name] = $current;

            $ownBody = $current->stmts ?? [];
            foreach ($ownBody as $statement) {
                $result[] = $statement;
            }

            foreach (array_reverse($this->helperMethodsCalledBy($ownBody, $methodsByName)) as $helperMethod) {
                $stack[] = $helperMethod;
            }
        }

        return $result;
    }

    /**
     * Indexes, once per class, which methods call which and the calls each
     * method holds that `$isRelevant` accepts.
     *
     * @param array<string, ClassMethod>                              $methodsByName
     * @param Closure(MethodCall|NullsafeMethodCall|StaticCall): bool $isRelevant
     */
    public function indexCalls(array $methodsByName, Closure $isRelevant): ReachableCallIndex
    {
        $helpersByMethod = [];
        $relevantCallsByMethod = [];
        foreach ($methodsByName as $name => $classMethod) {
            $calls = $this->callsIn($classMethod->stmts ?? []);
            $helpersByMethod[$name] = $this->helperNamesCalledBy($calls, $methodsByName);
            $relevantCallsByMethod[$name] = array_filter($calls, $isRelevant);
        }

        return new ReachableCallIndex($helpersByMethod, $relevantCallsByMethod);
    }

    /**
     * @param array<Node>                $ownBody
     * @param array<string, ClassMethod> $methodsByName
     *
     * @return list<ClassMethod>
     */
    private function helperMethodsCalledBy(array $ownBody, array $methodsByName): array
    {
        return array_map(
            static fn (string $name): ClassMethod => $methodsByName[$name],
            $this->helperNamesCalledBy($this->callsIn($ownBody), $methodsByName),
        );
    }

    /**
     * @param array<Node> $nodes
     *
     * @return array<MethodCall|NullsafeMethodCall|StaticCall>
     */
    private function callsIn(array $nodes): array
    {
        return [
            ...$this->nodeFinder->findInstanceOf($nodes, MethodCall::class),
            ...$this->nodeFinder->findInstanceOf($nodes, NullsafeMethodCall::class),
            ...$this->nodeFinder->findInstanceOf($nodes, StaticCall::class),
        ];
    }

    /**
     * @param array<MethodCall|NullsafeMethodCall|StaticCall> $methodCalls
     * @param array<string, ClassMethod>                      $methodsByName
     *
     * @return list<string>
     */
    private function helperNamesCalledBy(array $methodCalls, array $methodsByName): array
    {
        $helperNames = [];
        foreach ($methodCalls as $methodCall) {
            $calledName = $this->calledMethodName($methodCall);
            if (null !== $calledName && \array_key_exists($calledName, $methodsByName)) {
                $helperNames[] = $calledName;
            }
        }

        return $helperNames;
    }

    private function calledMethodName(MethodCall|NullsafeMethodCall|StaticCall $call): ?string
    {
        if ($call->isFirstClassCallable()) {
            return null;
        }

        return $call instanceof StaticCall ? $this->selfStaticCallName($call) : $this->thisCallName($call);
    }

    private function thisCallName(MethodCall|NullsafeMethodCall $methodCall): ?string
    {
        if (!$methodCall->var instanceof Variable || 'this' !== $methodCall->var->name) {
            return null;
        }

        return $methodCall->name instanceof Identifier ? $methodCall->name->toString() : null;
    }

    private function selfStaticCallName(StaticCall $staticCall): ?string
    {
        if (!$staticCall->class instanceof Name || !\in_array($staticCall->class->toString(), ['self', 'static'], true)) {
            return null;
        }

        return $staticCall->name instanceof Identifier ? $staticCall->name->toString() : null;
    }
}
