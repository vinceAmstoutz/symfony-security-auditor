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
use PhpParser\Node\AttributeGroup;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;

/**
 * The class constant a guard passes as its attribute instead of a literal —
 * `#[IsGranted(PostVoter::EDIT)]`, `denyAccessUnlessGranted(PostVoter::EDIT)`
 * — as `Fully\Qualified\Class::NAME`, read from an AST whose names are already
 * resolved against their imports. Which string the constant holds is left to
 * a caller that knows the class.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class GuardConstantReader
{
    public function __construct(
        private IsGrantedAttributeParser $isGrantedAttributeParser = new IsGrantedAttributeParser(),
    ) {}

    /**
     * @param array<AttributeGroup> $attributeGroups
     *
     * @return list<string>
     */
    public function fromAttributes(array $attributeGroups): array
    {
        $constants = [];
        foreach ($attributeGroups as $attributeGroup) {
            foreach ($attributeGroup->attrs as $attribute) {
                $constant = $this->constantOf($this->isGrantedAttributeParser->valueArgument($attribute)?->value);
                if (null !== $constant) {
                    $constants[] = $constant;
                }
            }
        }

        return $constants;
    }

    public function fromFirstArgument(MethodCall|NullsafeMethodCall|StaticCall $call): ?string
    {
        $firstArgument = $call->args[0] ?? null;

        return $firstArgument instanceof Arg ? $this->constantOf($firstArgument->value) : null;
    }

    private function constantOf(?Expr $expr): ?string
    {
        if (!$expr instanceof ClassConstFetch || !$expr->class instanceof Name || !$expr->name instanceof Identifier) {
            return null;
        }

        return \sprintf('%s::%s', $expr->class->toString(), $expr->name->toString());
    }
}
