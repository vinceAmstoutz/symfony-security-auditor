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
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\ShouldNotHappenException;

/**
 * @implements Rule<Node>
 */
final readonly class ForbiddenNodeRule implements Rule
{
    /**
     * @param list<class-string<Node>> $forbiddenNodes
     */
    public function __construct(private array $forbiddenNodes) {}

    #[Override]
    public function getNodeType(): string
    {
        return Node::class;
    }

    /**
     * @return list<IdentifierRuleError>
     *
     * @throws ShouldNotHappenException
     */
    #[Override]
    public function processNode(Node $node, Scope $scope): array
    {
        foreach ($this->forbiddenNodes as $forbiddenNode) {
            if ($node instanceof $forbiddenNode) {
                return [
                    RuleErrorBuilder::message(\sprintf('"%s" is forbidden to use', $node->getType()))
                        ->identifier('ssa.forbiddenNode')
                        ->build(),
                ];
            }
        }

        return [];
    }
}
