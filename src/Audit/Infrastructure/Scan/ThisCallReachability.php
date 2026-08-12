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
 * Follows `$this->helper()` calls from a starting method into other methods
 * declared on the same class, returning every statement node transitively
 * reachable from it — with cycle protection for mutually-calling helpers.
 * Lets an AST parser see through a common refactor: a check it looks for
 * (a security call, an attribute/subject test) moved behind a shared
 * private/protected helper instead of inlined in the method the parser scans.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ThisCallReachability
{
    public function __construct(
        private NodeFinder $nodeFinder = new NodeFinder(),
    ) {}

    /**
     * Walks the call graph depth-first with an explicit stack, visiting each
     * method's helper calls in the order they appear (pushed in reverse, so
     * the first call encountered is the next one popped) and appending each
     * statement once to a single shared result — replacing an earlier
     * recursive version that copied a growing `$visited` set and
     * return-and-concatenated a growing result array at every recursion
     * level. That was quadratic in the length of a
     * `$this->b1()->b2()->…` helper chain: an ordinary-looking file with a
     * few thousand such methods took minutes, and enough of them exhausted
     * PHP's memory limit outright, instead of resolving in a fraction of a
     * second.
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

            $helperMethods = $this->helperMethodsCalledBy($ownBody, $methodsByName);
            for ($i = \count($helperMethods) - 1; $i >= 0; --$i) {
                $stack[] = $helperMethods[$i];
            }
        }

        return $result;
    }

    /**
     * @param array<Node>                $ownBody
     * @param array<string, ClassMethod> $methodsByName
     *
     * @return list<ClassMethod>
     */
    private function helperMethodsCalledBy(array $ownBody, array $methodsByName): array
    {
        $methodCalls = [
            ...$this->nodeFinder->findInstanceOf($ownBody, MethodCall::class),
            ...$this->nodeFinder->findInstanceOf($ownBody, NullsafeMethodCall::class),
            ...$this->nodeFinder->findInstanceOf($ownBody, StaticCall::class),
        ];

        $helperMethods = [];
        foreach ($methodCalls as $methodCall) {
            $calledName = $this->calledMethodName($methodCall);
            if (null !== $calledName && \array_key_exists($calledName, $methodsByName)) {
                $helperMethods[] = $methodsByName[$calledName];
            }
        }

        return $helperMethods;
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
