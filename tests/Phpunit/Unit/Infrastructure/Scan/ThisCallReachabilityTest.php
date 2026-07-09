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

use Override;
use PhpParser\Node;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\ThisCallReachability;

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
