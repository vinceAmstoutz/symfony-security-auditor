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

use PhpParser\Comment\Doc;
use PhpParser\Node;
use PhpParser\Node\Stmt\ClassMethod;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\ShouldNotHappenException;

/**
 * @implements Rule<ClassMethod>
 */
final readonly class MaxParameterCountRule implements Rule
{
    private const int MAX_PARAMETERS = 5;

    public function getNodeType(): string
    {
        return ClassMethod::class;
    }

    /**
     * @return list<IdentifierRuleError>
     *
     * @throws ShouldNotHappenException
     */
    public function processNode(Node $node, Scope $scope): array
    {
        $parameterCount = \count($node->params);
        if ($parameterCount <= self::MAX_PARAMETERS) {
            return [];
        }

        if ($this->isAllPromotedConstructor($node)) {
            return [];
        }

        if ($this->isDeprecated($node)) {
            return [];
        }

        return [
            RuleErrorBuilder::message(\sprintf(
                'Method %s() declares %d parameters; the maximum allowed is %d. Bundle related parameters into a value object.',
                $node->name->toString(),
                $parameterCount,
                self::MAX_PARAMETERS,
            ))->identifier('ssa.maxParameterCount')->build(),
        ];
    }

    private function isAllPromotedConstructor(ClassMethod $classMethod): bool
    {
        if ('__construct' !== $classMethod->name->toLowerString()) {
            return false;
        }

        foreach ($classMethod->params as $param) {
            if (0 === $param->flags) {
                return false;
            }
        }

        return [] !== $classMethod->params;
    }

    private function isDeprecated(ClassMethod $classMethod): bool
    {
        $docComment = $classMethod->getDocComment();

        return $docComment instanceof Doc && str_contains($docComment->getText(), '@deprecated');
    }
}
