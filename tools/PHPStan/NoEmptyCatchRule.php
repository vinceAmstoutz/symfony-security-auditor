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
use PhpParser\Node\Stmt\Catch_;
use PhpParser\Node\Stmt\Nop;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\ShouldNotHappenException;

/**
 * @implements Rule<Catch_>
 */
final readonly class NoEmptyCatchRule implements Rule
{
    public function getNodeType(): string
    {
        return Catch_::class;
    }

    /**
     * @return list<IdentifierRuleError>
     * @throws ShouldNotHappenException
     */
    public function processNode(Node $node, Scope $scope): array
    {
        $meaningfulStatements = array_filter($node->stmts, static fn (Node $statement): bool => !$statement instanceof Nop);
        if ([] !== $meaningfulStatements) {
            return [];
        }

        return [
            RuleErrorBuilder::message('Empty catch block (or comment-only) is forbidden; handle or at least log the caught exception.')
                ->identifier('ssa.noEmptyCatch')
                ->build(),
        ];
    }
}
