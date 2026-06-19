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

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Return_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\ShouldNotHappenException;

/**
 * Forbids set_error_handler() with a callback that merely returns true — a
 * blanket silencer that swallows every error just like the @ operator.
 *
 * @implements Rule<FuncCall>
 */
final readonly class NoSilencingErrorHandlerRule implements Rule
{
    public function getNodeType(): string
    {
        return FuncCall::class;
    }

    /**
     * @return list<IdentifierRuleError>
     *
     * @throws ShouldNotHappenException
     */
    public function processNode(Node $node, Scope $scope): array
    {
        if (!$node->name instanceof Name) {
            return [];
        }

        if ('set_error_handler' !== $node->name->toLowerString()) {
            return [];
        }

        $arguments = $node->getArgs();
        if ([] === $arguments) {
            return [];
        }

        if (!$this->isBlanketSilencer($arguments[0]->value)) {
            return [];
        }

        return [
            RuleErrorBuilder::message('set_error_handler() with a callback that only returns true silently swallows every error; capture or convert the error instead, or remove the suppression.')
                ->identifier('ssa.noSilencingErrorHandler')
                ->build(),
        ];
    }

    private function isBlanketSilencer(Expr $expr): bool
    {
        if ($expr instanceof ArrowFunction) {
            return $this->isTrueLiteral($expr->expr);
        }

        if ($expr instanceof Closure) {
            return 1 === \count($expr->stmts)
                && $expr->stmts[0] instanceof Return_
                && $expr->stmts[0]->expr instanceof Expr
                && $this->isTrueLiteral($expr->stmts[0]->expr);
        }

        return false;
    }

    private function isTrueLiteral(Expr $expr): bool
    {
        return $expr instanceof ConstFetch && 'true' === $expr->name->toLowerString();
    }
}
