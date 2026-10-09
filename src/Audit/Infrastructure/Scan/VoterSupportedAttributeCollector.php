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
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\NodeFinder;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class VoterSupportedAttributeCollector
{
    public function __construct(
        private NodeFinder $nodeFinder = new NodeFinder(),
    ) {}

    /**
     * @param array<Node> $body
     *
     * @return list<string>
     */
    public function collect(array $body, Class_ $class): array
    {
        return array_values(array_unique([
            ...$this->collectStringLiterals($body),
            ...$this->collectSelfConstantFetches($body, $this->resolveOwnConstants($class)),
        ]));
    }

    /**
     * @param array<Node> $body
     *
     * @return list<string>
     */
    private function collectStringLiterals(array $body): array
    {
        $values = [];
        $stringNodes = $this->nodeFinder->findInstanceOf($body, String_::class);
        foreach ($stringNodes as $stringNode) {
            if ('' !== $stringNode->value) {
                $values[] = $stringNode->value;
            }
        }

        return $values;
    }

    /**
     * Resolves `self::EDIT`/`static::EDIT` fetches in `$body` against the
     * voter's own class constants — the canonical Symfony voter pattern
     * (`const EDIT = 'edit'; ... in_array($attribute, [self::EDIT, ...])`)
     * has no bare string literal for `collectStringLiterals()` to find. A
     * constant naming an array of strings (`const SUPPORTED = ['edit', ...];
     * ... in_array($attribute, self::SUPPORTED, true)`) resolves to every
     * string element it holds.
     *
     * @param array<Node>                 $body
     * @param array<string, list<string>> $constantValues
     *
     * @return list<string>
     */
    private function collectSelfConstantFetches(array $body, array $constantValues): array
    {
        $values = [];
        foreach (array_keys($this->fetchedConstantNames($body)) as $name) {
            array_push($values, ...($constantValues[$name] ?? []));
        }

        return $values;
    }

    /**
     * The names of the own constants `$body` fetches, each once, in the order
     * they are first fetched — so a constant fetched thousands of times is
     * expanded once, not once per fetch.
     *
     * @param array<Node> $body
     *
     * @return array<string, true>
     */
    private function fetchedConstantNames(array $body): array
    {
        $names = [];
        $constFetchNodes = $this->nodeFinder->findInstanceOf($body, ClassConstFetch::class);
        foreach ($constFetchNodes as $constFetchNode) {
            $name = $this->selfConstantName($constFetchNode);
            if (null !== $name) {
                $names[$name] = true;
            }
        }

        return $names;
    }

    private function selfConstantName(ClassConstFetch $classConstFetch): ?string
    {
        if (!$classConstFetch->class instanceof Name || !\in_array($classConstFetch->class->toString(), ['self', 'static'], true)) {
            return null;
        }

        return $classConstFetch->name instanceof Identifier ? $classConstFetch->name->toString() : null;
    }

    /**
     * @return array<string, list<string>>
     */
    private function resolveOwnConstants(Class_ $class): array
    {
        $constantValues = [];
        foreach ($class->getConstants() as $classConst) {
            foreach ($classConst->consts as $const) {
                $values = $this->stringValuesFromConstExpr($const->value);
                if ([] !== $values) {
                    $constantValues[$const->name->toString()] = $values;
                }
            }
        }

        return $constantValues;
    }

    /**
     * @return list<string>
     */
    private function stringValuesFromConstExpr(Expr $expr): array
    {
        if ($expr instanceof String_) {
            return [$expr->value];
        }

        if (!$expr instanceof Array_) {
            return [];
        }

        $values = [];
        foreach ($expr->items as $item) {
            if ($item->value instanceof String_) {
                $values[] = $item->value->value;
            }
        }

        return $values;
    }
}
