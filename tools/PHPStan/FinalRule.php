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
use PhpParser\Node\Stmt\Class_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\ShouldNotHappenException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;

/**
 * @implements Rule<Class_>
 */
final readonly class FinalRule implements Rule
{
    /**
     * Concrete base exceptions that are extended by subtypes yet also thrown
     * directly — cannot be final (extended) nor abstract (instantiated).
     *
     * @var list<string>
     */
    private const array ALLOWED_NON_FINAL = [LLMProviderException::class];

    #[Override]
    public function getNodeType(): string
    {
        return Class_::class;
    }

    /**
     * @return list<IdentifierRuleError>
     *
     * @throws ShouldNotHappenException
     */
    #[Override]
    public function processNode(Node $node, Scope $scope): array
    {
        if ($node->isFinal() || $node->isAbstract() || $node->isAnonymous()) {
            return [];
        }

        $name = $node->namespacedName?->toString() ?? $node->name?->toString();
        if (null === $name || \in_array($name, self::ALLOWED_NON_FINAL, true)) {
            return [];
        }

        return [
            RuleErrorBuilder::message(\sprintf('Class %s must be final or abstract.', $name))
                ->identifier('ssa.final')
                ->build(),
        ];
    }
}
