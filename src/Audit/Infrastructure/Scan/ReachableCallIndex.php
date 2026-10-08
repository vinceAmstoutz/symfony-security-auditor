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

use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Stmt\ClassMethod;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Answers, for any method of one class, which of the calls a parser looks for
 * the method reaches through `$this->helper()` calls — in the order a
 * depth-first walk from it meets them, each helper once. Built once per class
 * by {@see ThisCallReachability::indexCalls()}, so that asking every public
 * action costs a walk over the few methods that matter to it, not over every
 * helper it ever reaches: a helper from which no relevant call is reachable
 * is never entered, and a helper that only forwards to one other is stepped
 * over. A chain of thousands of single-call helpers then costs the same for
 * its first method as for its last.
 */
final readonly class ReachableCallIndex
{
    /** @var array<string, list<string>> the methods a walk goes on to from each method it can stop at */
    private array $nextSteps;

    /** @var array<string, string> the method each forwarding method leads to, once every forward is followed */
    private array $forwardEnds;

    /**
     * @param array<string, list<string>>                                    $helpersByMethod       the same-class methods each method calls, in call order
     * @param array<string, array<MethodCall|NullsafeMethodCall|StaticCall>> $relevantCallsByMethod the calls each method holds that the parser looks for
     */
    public function __construct(array $helpersByMethod, private array $relevantCallsByMethod)
    {
        $reachingHelpers = $this->reachingHelpers($helpersByMethod, $relevantCallsByMethod);
        $this->forwardEnds = $this->forwardEnds($this->forwardedCalls($reachingHelpers, $relevantCallsByMethod));
        $this->nextSteps = $this->nextSteps($reachingHelpers, $this->forwardEnds);
    }

    /**
     * @return list<MethodCall|NullsafeMethodCall|StaticCall>
     */
    public function callsFrom(ClassMethod $classMethod): array
    {
        $calls = [];
        foreach ($this->walkFrom($classMethod->name->toString()) as $name) {
            foreach ($this->relevantCallsByMethod[$name] as $call) {
                $calls[] = $call;
            }
        }

        return $calls;
    }

    /**
     * @return list<string> the methods a walk from the named method stops at: the ones holding a relevant call and the ones where the walk forks
     */
    public function walkFrom(string $methodName): array
    {
        $start = $this->forwardEnds[$methodName] ?? $methodName;
        if (!\array_key_exists($start, $this->nextSteps)) {
            return [];
        }

        $walk = [];
        $stack = [$start];
        while ([] !== $stack) {
            $name = array_pop($stack);
            if (\array_key_exists($name, $walk)) {
                continue;
            }

            $walk[$name] = $name;

            $steps = $this->nextSteps[$name];
            for ($i = \count($steps) - 1; $i >= 0; --$i) {
                $stack[] = $steps[$i];
            }
        }

        return array_keys($walk);
    }

    /**
     * Keeps, for each method from which a relevant call is reachable, only the
     * helpers it calls that share that property, each once.
     *
     * @param array<string, list<string>>                                    $helpersByMethod
     * @param array<string, array<MethodCall|NullsafeMethodCall|StaticCall>> $relevantCallsByMethod
     *
     * @return array<string, list<string>>
     */
    private function reachingHelpers(array $helpersByMethod, array $relevantCallsByMethod): array
    {
        $reaching = $this->methodsReachingACall($helpersByMethod, $relevantCallsByMethod);

        $reachingHelpers = [];
        foreach (array_keys($reaching) as $name) {
            $reachingHelpers[$name] = array_values(array_unique(array_filter(
                $helpersByMethod[$name],
                static fn (string $helper): bool => \array_key_exists($helper, $reaching),
            )));
        }

        return $reachingHelpers;
    }

    /**
     * @param array<string, list<string>>                                    $helpersByMethod
     * @param array<string, array<MethodCall|NullsafeMethodCall|StaticCall>> $relevantCallsByMethod
     *
     * @return array<string, null>
     */
    private function methodsReachingACall(array $helpersByMethod, array $relevantCallsByMethod): array
    {
        $callers = $this->callersByMethod($helpersByMethod);
        $queue = $this->methodsHoldingACall($relevantCallsByMethod);
        $reaching = array_fill_keys($queue, null);
        for ($i = 0; \array_key_exists($i, $queue); ++$i) {
            foreach ($callers[$queue[$i]] ?? [] as $caller) {
                if (!\array_key_exists($caller, $reaching)) {
                    $reaching[$caller] = null;
                    $queue[] = $caller;
                }
            }
        }

        return $reaching;
    }

    /**
     * @param array<string, array<MethodCall|NullsafeMethodCall|StaticCall>> $relevantCallsByMethod
     *
     * @return list<string>
     */
    private function methodsHoldingACall(array $relevantCallsByMethod): array
    {
        return array_keys(array_filter($relevantCallsByMethod, static fn (array $calls): bool => [] !== $calls));
    }

    /**
     * @param array<string, list<string>> $helpersByMethod
     *
     * @return array<string, list<string>>
     */
    private function callersByMethod(array $helpersByMethod): array
    {
        $callers = [];
        foreach ($helpersByMethod as $caller => $helpers) {
            foreach ($helpers as $helper) {
                $callers[$helper][] = $caller;
            }
        }

        return $callers;
    }

    /**
     * The methods that hold no relevant call and lead to exactly one other
     * method, with the method they lead to.
     *
     * @param array<string, list<string>>                                    $reachingHelpers
     * @param array<string, array<MethodCall|NullsafeMethodCall|StaticCall>> $relevantCallsByMethod
     *
     * @return array<string, string>
     */
    private function forwardedCalls(array $reachingHelpers, array $relevantCallsByMethod): array
    {
        $forwarded = [];
        foreach ($reachingHelpers as $name => $helpers) {
            if ([] === $relevantCallsByMethod[$name] && 1 === \count($helpers)) {
                $forwarded[$name] = $helpers[0];
            }
        }

        return $forwarded;
    }

    /**
     * Follows every forward to the method it ends at, pointing each forward it
     * passes straight at that end so no later one walks the same stretch again.
     *
     * @param array<string, string> $forwarded
     *
     * @return array<string, string>
     */
    private function forwardEnds(array $forwarded): array
    {
        foreach (array_keys($forwarded) as $name) {
            $passed = [];
            $end = $name;
            while (\array_key_exists($end, $forwarded)) {
                $passed[] = $end;
                $end = $forwarded[$end];
            }

            foreach ($passed as $step) {
                $forwarded[$step] = $end;
            }
        }

        return $forwarded;
    }

    /**
     * @param array<string, list<string>> $reachingHelpers
     * @param array<string, string>       $forwardEnds
     *
     * @return array<string, list<string>>
     */
    private function nextSteps(array $reachingHelpers, array $forwardEnds): array
    {
        $nextSteps = [];
        foreach ($reachingHelpers as $name => $helpers) {
            if (\array_key_exists($name, $forwardEnds)) {
                continue;
            }

            $nextSteps[$name] = array_map(
                static fn (string $helper): string => $forwardEnds[$helper] ?? $helper,
                $helpers,
            );
        }

        return $nextSteps;
    }
}
