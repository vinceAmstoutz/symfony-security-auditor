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

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\ThisCallReachability;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan\Fixture\CountingNodeFinder;

final class ThisCallReachabilityTest extends TestCase
{
    private ThisCallReachability $thisCallReachability;

    #[Override]
    protected function setUp(): void
    {
        $this->thisCallReachability = new ThisCallReachability();
    }

    public function test_it_returns_only_the_starting_methods_own_body_when_it_calls_no_helper(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    echo 'own-body';
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame(['own-body'], $this->stringLiteralsIn($body));
    }

    public function test_it_includes_a_directly_called_helpers_body(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    $this->helper();
                }
                private function helper(): void {
                    echo 'from-helper';
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame(['from-helper'], $this->stringLiteralsIn($body));
    }

    public function test_it_follows_a_chain_of_helper_calls_two_levels_deep(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    $this->helperOne();
                }
                private function helperOne(): void {
                    $this->helperTwo();
                }
                private function helperTwo(): void {
                    echo 'deeply-nested';
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame(['deeply-nested'], $this->stringLiteralsIn($body));
    }

    public function test_it_includes_a_helpers_body_reached_through_a_self_static_call(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    self::helper();
                }
                private static function helper(): void {
                    echo 'from-static-helper';
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame(['from-static-helper'], $this->stringLiteralsIn($body));
    }

    public function test_it_includes_a_helpers_body_reached_through_a_static_keyword_call(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    static::helper();
                }
                private static function helper(): void {
                    echo 'from-late-static-helper';
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame(['from-late-static-helper'], $this->stringLiteralsIn($body));
    }

    public function test_it_ignores_a_first_class_callable_reference_to_a_helper(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    $callback = $this->helper(...);
                    unset($callback);
                }
                private function helper(): void {
                    echo 'from-helper';
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame([], $this->stringLiteralsIn($body));
    }

    public function test_it_ignores_a_this_call_to_a_method_the_class_does_not_declare(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    echo 'own-body';
                    $this->inheritedHelper();
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame(['own-body'], $this->stringLiteralsIn($body));
    }

    public function test_it_ignores_a_static_call_to_another_classs_method(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    OtherClass::helper();
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame([], $this->stringLiteralsIn($body));
    }

    public function test_it_ignores_a_call_to_a_method_not_declared_on_the_same_class(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    $this->logger->info('not-a-same-class-method');
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame(['not-a-same-class-method'], $this->stringLiteralsIn($body));
    }

    public function test_it_does_not_infinitely_recurse_when_helpers_call_each_other_in_a_cycle(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    $this->helperOne();
                }
                private function helperOne(): void {
                    echo 'one';
                    $this->helperTwo();
                }
                private function helperTwo(): void {
                    echo 'two';
                    $this->helperOne();
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame(['one', 'two'], $this->stringLiteralsIn($body));
    }

    public function test_it_includes_the_bodies_of_every_helper_a_method_calls_not_only_the_last(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    $this->helperOne();
                    $this->helperTwo();
                }
                private function helperOne(): void {
                    echo 'one';
                }
                private function helperTwo(): void {
                    echo 'two';
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame(['one', 'two'], $this->stringLiteralsIn($body));
    }

    public function test_it_continues_past_an_already_visited_helper_to_process_the_remaining_call_sites(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    $this->helperA();
                    $this->helperB();
                    $this->helperC();
                }
                private function helperA(): void {
                    echo 'a';
                    $this->helperB();
                }
                private function helperB(): void {
                    echo 'b';
                }
                private function helperC(): void {
                    echo 'c';
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame(['a', 'b', 'c'], $this->stringLiteralsIn($body));
    }

    public function test_it_ignores_a_method_call_on_a_variable_other_than_this(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    $other->helper();
                }
                private function helper(): void {
                    echo 'should-not-appear';
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame([], $this->stringLiteralsIn($body));
    }

    public function test_it_ignores_a_static_call_to_another_class_even_when_the_method_name_matches_a_local_one(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    OtherClass::helper();
                }
                private static function helper(): void {
                    echo 'should-not-appear';
                }
            }
            PHP);

        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));

        self::assertSame([], $this->stringLiteralsIn($body));
    }

    public function test_it_indexes_the_relevant_calls_an_action_reaches_through_its_helpers(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    $this->probe('own');
                    $this->helper();
                }
                private function helper(): void {
                    $this->probe('helper');
                    $this->logger->info('ignored');
                }
                private function unreachable(): void {
                    $this->probe('unreachable');
                }
            }
            PHP);

        $calls = $this->thisCallReachability
            ->indexCalls($this->methodsByName($class), $this->isProbe(...))
            ->callsFrom($this->methodNamed($class, 'action'));

        self::assertSame(['own', 'helper'], $this->labelsOf($calls));
    }

    public function test_it_indexes_relevant_calls_of_every_call_kind(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    Other::probe('static');
                    $this?->probe('nullsafe');
                    $this->probe('plain');
                }
            }
            PHP);

        $calls = $this->thisCallReachability
            ->indexCalls($this->methodsByName($class), $this->isProbe(...))
            ->callsFrom($this->methodNamed($class, 'action'));

        self::assertSame(['plain', 'nullsafe', 'static'], $this->labelsOf($calls));
    }

    public function test_it_indexes_relevant_calls_behind_helpers_called_through_every_call_kind(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function action(): void {
                    $this?->viaNullsafe();
                    self::viaSelf();
                    static::viaStatic();
                    $callback = $this->viaCallable(...);
                }
                private function viaNullsafe(): void { $this->probe('nullsafe'); }
                private static function viaSelf(): void { self::probe('self'); }
                private static function viaStatic(): void { static::probe('static'); }
                private function viaCallable(): void { $this->probe('callable'); }
                public function probe(string $label): void {}
            }
            PHP);

        $calls = $this->thisCallReachability
            ->indexCalls($this->methodsByName($class), $this->isProbe(...))
            ->callsFrom($this->methodNamed($class, 'action'));

        self::assertSame(['nullsafe', 'self', 'static'], $this->labelsOf($calls));
    }

    public function test_it_indexes_the_relevant_calls_of_each_action_separately(): void
    {
        $class = $this->parseClass(<<<'PHP'
            <?php
            final class Example {
                public function first(): void { $this->shared(); }
                public function second(): void { $this->probe('second'); }
                private function shared(): void { $this->probe('shared'); }
            }
            PHP);

        $reachableCallIndex = $this->thisCallReachability->indexCalls($this->methodsByName($class), $this->isProbe(...));

        self::assertSame(['shared'], $this->labelsOf($reachableCallIndex->callsFrom($this->methodNamed($class, 'first'))));
        self::assertSame(['second'], $this->labelsOf($reachableCallIndex->callsFrom($this->methodNamed($class, 'second'))));
    }

    #[MaximumDuration(4000)]
    public function test_a_long_chain_of_actions_walks_each_syntax_node_a_bounded_number_of_times(): void
    {
        $chainLength = 500;
        $methods = '';
        for ($i = 0; $i < $chainLength; ++$i) {
            $methods .= \sprintf("public function action%d(): void { \$this->action%d(); }\n", $i, $i + 1);
        }

        $methods .= \sprintf("public function action%d(): void { \$this->probe('end'); }\n", $chainLength);
        $class = $this->parseClass("<?php\nfinal class Example {\n{$methods}}\n");
        $countingNodeFinder = new CountingNodeFinder();

        $calls = (new ThisCallReachability($countingNodeFinder))
            ->indexCalls($this->methodsByName($class), $this->isProbe(...))
            ->callsFrom($this->methodNamed($class, 'action0'));

        self::assertSame(['end'], $this->labelsOf($calls));
        self::assertLessThan(4 * \count((new CountingNodeFinder())->findInstanceOf([$class], Node::class)), $countingNodeFinder->visitedNodes);
    }

    #[MaximumDuration(4000)]
    public function test_a_long_chain_of_helper_calls_resolves_in_near_linear_time(): void
    {
        $chainLength = 8000;
        $methods = "public function action(): void { \$this->helper1(); }\n";
        for ($i = 1; $i < $chainLength; ++$i) {
            $next = $i + 1;
            $methods .= "private function helper{$i}(): void { echo 'x'; \$this->helper{$next}(); }\n";
        }

        $methods .= "private function helper{$chainLength}(): void { echo 'end'; }\n";

        $class = $this->parseClass("<?php\nfinal class Example {\n{$methods}}\n");

        $start = microtime(true);
        $body = $this->thisCallReachability->reachableBody($this->methodNamed($class, 'action'), $this->methodsByName($class));
        $elapsed = microtime(true) - $start;

        self::assertCount($chainLength, $this->stringLiteralsIn($body));
        self::assertLessThan(3.0, $elapsed);
    }

    private function isProbe(MethodCall|NullsafeMethodCall|StaticCall $call): bool
    {
        return $call->name instanceof Identifier && 'probe' === $call->name->toString();
    }

    /**
     * @param list<MethodCall|NullsafeMethodCall|StaticCall> $calls
     *
     * @return list<string>
     */
    private function labelsOf(array $calls): array
    {
        return array_map(static function (MethodCall|NullsafeMethodCall|StaticCall $call): string {
            $argument = $call->args[0];
            self::assertInstanceOf(Arg::class, $argument);
            self::assertInstanceOf(String_::class, $argument->value);

            return $argument->value->value;
        }, $calls);
    }

    private function parseClass(string $source): Class_
    {
        $parserFactory = new ParserFactory();
        $parser = $parserFactory->createForNewestSupportedVersion();
        $ast = $parser->parse($source) ?? [];

        $class = (new NodeFinder())->findFirstInstanceOf($ast, Class_::class);
        self::assertInstanceOf(Class_::class, $class);

        return $class;
    }

    private function methodNamed(Class_ $class, string $name): ClassMethod
    {
        foreach ($class->getMethods() as $classMethod) {
            if ($name === $classMethod->name->toString()) {
                return $classMethod;
            }
        }

        self::fail(\sprintf('Method "%s" not found.', $name));
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
     * @param array<Node> $body
     *
     * @return list<string>
     */
    private function stringLiteralsIn(array $body): array
    {
        return array_values(array_map(
            static fn (String_ $string): string => $string->value,
            (new NodeFinder())->findInstanceOf($body, String_::class),
        ));
    }
}
