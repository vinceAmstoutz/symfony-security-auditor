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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\PHPStan;

use Override;
use PhpParser\Node;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/**
 * Forbids building a string by concatenating a literal with an expression in
 * production code: `$dir.'/'.$name` reads worse than
 * `sprintf('%s/%s', $dir, $name)` and scatters the format across operators.
 *
 * Only flagged when the chain mixes at least one string literal with at least
 * one non-literal operand — pure `$a.$b` and literal-only concatenations are
 * left alone, as sprintf would not improve them.
 *
 * @implements Rule<Concat>
 */
final readonly class SprintfOverConcatRule implements Rule
{
    #[Override]
    public function getNodeType(): string
    {
        return Concat::class;
    }

    /**
     * @return list<IdentifierRuleError>
     */
    #[Override]
    public function processNode(Node $node, Scope $scope): array
    {
        if (!str_contains($scope->getFile(), '/src/')) {
            return [];
        }

        if (true !== $node->getAttribute(ConcatRootMarkingVisitor::ROOT_ATTRIBUTE)) {
            return [];
        }

        $leaves = $this->leafOperands($node);
        if (!$this->mixesLiteralWithExpression($leaves)) {
            return [];
        }

        return [
            RuleErrorBuilder::message("Build strings with sprintf() instead of '.' concatenation of a literal and an expression.")
                ->identifier('ssa.sprintfOverConcat')
                ->build(),
        ];
    }

    /**
     * @return list<Node\Expr>
     */
    private function leafOperands(Concat $concat): array
    {
        $leaves = [];

        foreach ([$concat->left, $concat->right] as $operand) {
            if ($operand instanceof Concat) {
                $leaves = [...$leaves, ...$this->leafOperands($operand)];

                continue;
            }

            $leaves[] = $operand;
        }

        return $leaves;
    }

    /**
     * @param list<Node\Expr> $leaves
     */
    private function mixesLiteralWithExpression(array $leaves): bool
    {
        $hasLiteral = false;
        $hasExpression = false;

        foreach ($leaves as $leaf) {
            if ($leaf instanceof String_) {
                $hasLiteral = true;

                continue;
            }

            $hasExpression = true;
        }

        return $hasLiteral && $hasExpression;
    }
}
