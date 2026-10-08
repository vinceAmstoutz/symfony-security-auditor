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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Stmt\ClassMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\ReachableCallIndex;

final class ReachableCallIndexTest extends TestCase
{
    /**
     * @param array<string, list<string>> $helpers
     * @param list<string>                $holdingACall
     * @param list<string>                $expectedWalk
     */
    #[DataProvider('walks')]
    public function test_a_walk_stops_only_where_a_relevant_call_is_held_or_the_walk_forks(array $helpers, array $holdingACall, string $start, array $expectedWalk): void
    {
        $reachableCallIndex = new ReachableCallIndex($helpers, $this->callsHeldBy(array_keys($helpers), $holdingACall));

        self::assertSame($expectedWalk, $reachableCallIndex->walkFrom($start));
    }

    /**
     * @return iterable<string, array{array<string, list<string>>, list<string>, string, list<string>}>
     */
    public static function walks(): iterable
    {
        yield 'a method that reaches no relevant call is not entered' => [['a' => ['b'], 'b' => ['c'], 'c' => []], [], 'a', []];
        yield 'a method holding a relevant call is where its own walk stops' => [['a' => []], ['a'], 'a', ['a']];
        yield 'a chain of single calls collapses to the method holding the relevant call' => [['a' => ['b'], 'b' => ['c'], 'c' => []], ['c'], 'a', ['c']];
        yield 'a method forwarding to a method that holds a call is stepped over' => [['a' => ['b'], 'b' => []], ['b'], 'a', ['b']];
        yield 'a forwarding method that is not the start is stepped over too' => [['a' => ['b'], 'b' => ['c'], 'c' => ['d'], 'd' => []], ['d'], 'b', ['d']];
        yield 'a forward met after the chain behind it is known ends where that chain ends' => [['b' => ['c'], 'a' => ['b'], 'c' => ['d'], 'd' => []], ['d'], 'a', ['d']];
        yield 'a method holding a call and calling another that holds one stops at both' => [['a' => ['b'], 'b' => []], ['a', 'b'], 'a', ['a', 'b']];
        yield 'a method holding a call and forwarding to another keeps both' => [['a' => ['b'], 'b' => ['c'], 'c' => []], ['a', 'c'], 'a', ['a', 'c']];
        yield 'a method holding no call and calling two that hold one forks' => [['a' => ['b', 'c'], 'b' => [], 'c' => []], ['b', 'c'], 'a', ['a', 'b', 'c']];
        yield 'the calls of a fork are walked in the order they are made' => [['a' => ['c', 'b'], 'b' => [], 'c' => []], ['b', 'c'], 'a', ['a', 'c', 'b']];
        yield 'a helper met twice is walked once' => [['a' => ['b', 'c'], 'b' => ['d'], 'c' => ['d'], 'd' => []], ['b', 'c', 'd'], 'a', ['a', 'b', 'd', 'c']];
        yield 'a helper called twice by one method does not make that method a fork' => [['a' => ['b', 'b'], 'b' => []], ['b'], 'a', ['b']];
        yield 'a helper that reaches no relevant call is left out of a fork' => [['a' => ['dead', 'b'], 'dead' => [], 'b' => []], ['b'], 'a', ['b']];
        yield 'a helper that reaches no relevant call is not entered from a method holding one' => [['a' => ['dead'], 'dead' => []], ['a'], 'a', ['a']];
        yield 'a method reaching a call only through another is walked to it' => [['a' => ['b'], 'b' => ['c', 'd'], 'c' => [], 'd' => []], ['c', 'd'], 'a', ['b', 'c', 'd']];
        yield 'helpers calling each other in a cycle are walked once' => [['a' => ['b'], 'b' => ['a', 'c'], 'c' => []], ['a', 'c'], 'a', ['a', 'b', 'c']];
        yield 'a forwarding method inside a cycle is stepped over' => [['a' => ['b'], 'b' => ['a', 'c'], 'c' => []], ['c'], 'a', ['b', 'c']];
        yield 'a method calling itself while holding a call is walked once' => [['a' => ['a']], ['a'], 'a', ['a']];
    }

    public function test_it_returns_the_relevant_calls_of_the_methods_a_walk_stops_at_in_walk_order(): void
    {
        $callsByMethod = ['a' => [$this->call('fromA')], 'b' => [$this->call('fromB')], 'c' => [$this->call('fromC')]];
        $reachableCallIndex = new ReachableCallIndex(['a' => ['c', 'b'], 'b' => [], 'c' => []], $callsByMethod);

        self::assertSame(
            [$callsByMethod['a'][0], $callsByMethod['c'][0], $callsByMethod['b'][0]],
            $reachableCallIndex->callsFrom(new ClassMethod('a')),
        );
    }

    public function test_it_returns_every_relevant_call_a_method_holds_in_the_order_they_were_given(): void
    {
        $methodCall = $this->call('first');
        $second = $this->call('second');
        $reachableCallIndex = new ReachableCallIndex(['a' => []], ['a' => [$methodCall, $second]]);

        self::assertSame([$methodCall, $second], $reachableCallIndex->callsFrom(new ClassMethod('a')));
    }

    public function test_it_returns_no_call_for_a_method_that_reaches_none(): void
    {
        $reachableCallIndex = new ReachableCallIndex(['a' => ['b'], 'b' => []], ['a' => [], 'b' => []]);

        self::assertSame([], $reachableCallIndex->callsFrom(new ClassMethod('a')));
    }

    public function test_a_chain_of_thousands_of_forwarding_methods_is_stepped_over_in_near_linear_time(): void
    {
        $chainLength = 20000;
        $helpers = [];
        $callsByMethod = [];
        for ($i = 0; $i < $chainLength; ++$i) {
            $helpers['m'.$i] = ['m'.($i + 1)];
            $callsByMethod['m'.$i] = [];
        }

        $helpers['m'.$chainLength] = [];
        $callsByMethod['m'.$chainLength] = [$this->call('guard')];

        $start = microtime(true);
        $reachableCallIndex = new ReachableCallIndex($helpers, $callsByMethod);
        $walks = array_map($reachableCallIndex->walkFrom(...), array_keys($helpers));
        $elapsed = microtime(true) - $start;

        self::assertSame(['m'.$chainLength], $walks[0]);
        self::assertSame(['m'.$chainLength], $walks[$chainLength - 1]);
        self::assertSame(['m'.$chainLength], $walks[$chainLength]);
        self::assertLessThan(2.0, $elapsed);
    }

    /**
     * @param list<string> $methods
     * @param list<string> $holdingACall
     *
     * @return array<string, list<MethodCall>>
     */
    private function callsHeldBy(array $methods, array $holdingACall): array
    {
        $calls = [];
        foreach ($methods as $method) {
            $calls[$method] = \in_array($method, $holdingACall, true) ? [$this->call($method)] : [];
        }

        return $calls;
    }

    private function call(string $name): MethodCall
    {
        return new MethodCall(new Variable('this'), $name);
    }
}
