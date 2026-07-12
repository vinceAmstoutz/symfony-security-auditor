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
     * @param array<string, ClassMethod> $methodsByName
     *
     * @return array<Node>
     */
    public function reachableBody(ClassMethod $classMethod, array $methodsByName): array
    {
        return $this->reachableBodyVisiting($classMethod, $methodsByName, []);
    }

    /**
     * @param array<string, ClassMethod> $methodsByName
     * @param array<string, true>        $visited
     *
     * @return array<Node>
     */
    private function reachableBodyVisiting(ClassMethod $classMethod, array $methodsByName, array $visited): array
    {
        $name = $classMethod->name->toString();
        if (\array_key_exists($name, $visited)) {
            return [];
        }

        $visited[$name] = true;

        $ownBody = $classMethod->stmts ?? [];

        $helperBody = [];
        $methodCalls = [
            ...$this->nodeFinder->findInstanceOf($ownBody, MethodCall::class),
            ...$this->nodeFinder->findInstanceOf($ownBody, NullsafeMethodCall::class),
            ...$this->nodeFinder->findInstanceOf($ownBody, StaticCall::class),
        ];
        foreach ($methodCalls as $methodCall) {
            $calledName = $this->calledMethodName($methodCall);
            if (null !== $calledName && \array_key_exists($calledName, $methodsByName)) {
                $helperBody = [...$helperBody, ...$this->reachableBodyVisiting($methodsByName[$calledName], $methodsByName, $visited)];
            }
        }

        return [...$ownBody, ...$helperBody];
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
