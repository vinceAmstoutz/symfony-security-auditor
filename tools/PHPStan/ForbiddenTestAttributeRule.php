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
use PhpParser\Node\Attribute;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\ShouldNotHappenException;

/**
 * Bans test attributes that opt out of a quality gate instead of fixing the
 * underlying test (mirrors the no-silence policy for PHPStan/Infection).
 *
 * #[IgnoreDeprecations] is the sole conditional case: it is allowed only when it
 * scopes the ignore to this library's own deprecations and the method asserts
 * them, so a first-party deprecation can be tested without ever silencing a
 * third-party one.
 *
 * @implements Rule<ClassMethod>
 */
final readonly class ForbiddenTestAttributeRule implements Rule
{
    private const string OWN_PACKAGE = 'vinceamstoutz/symfony-security-auditor';

    private const string IGNORE_DEPRECATIONS = 'IgnoreDeprecations';

    /**
     * @var list<non-empty-string>
     */
    private const array ASSERTION_METHODS = ['expectUserDeprecationMessage', 'expectUserDeprecationMessageMatches'];

    /**
     * @var array<string, string>
     */
    private const array FORBIDDEN = [
        'AllowMockObjectsWithoutExpectations' => 'use a stub (createStub) for a collaborator with no configured expectations',
        'DoesNotPerformAssertions' => 'assert a real outcome instead of declaring the test asserts nothing',
        self::IGNORE_DEPRECATIONS => "scope it to this library's own deprecations (#[IgnoreDeprecations('".self::OWN_PACKAGE."')]) and assert them with expectUserDeprecationMessage*(), never to silence a third-party deprecation",
        'WithoutErrorHandler' => 'keep the error handler so failOnWarning/failOnNotice still apply',
    ];

    #[Override]
    public function getNodeType(): string
    {
        return ClassMethod::class;
    }

    /**
     * @return list<IdentifierRuleError>
     *
     * @throws ShouldNotHappenException
     */
    #[Override]
    public function processNode(Node $node, Scope $scope): array
    {
        $errors = [];
        foreach ($this->forbiddenAttributes($node) as [$attribute, $name, $reason]) {
            if ($this->isAllowed($attribute, $node)) {
                continue;
            }

            $errors[] = RuleErrorBuilder::message(\sprintf('Attribute #[%s] is forbidden — %s.', $name, $reason))
                ->identifier('ssa.forbiddenTestAttribute')
                ->build();
        }

        return $errors;
    }

    /**
     * @return iterable<array{Attribute, string, string}>
     */
    private function forbiddenAttributes(ClassMethod $classMethod): iterable
    {
        foreach ($classMethod->attrGroups as $group) {
            foreach ($group->attrs as $attribute) {
                $name = $attribute->name->getLast();
                if (\array_key_exists($name, self::FORBIDDEN)) {
                    yield [$attribute, $name, self::FORBIDDEN[$name]];
                }
            }
        }
    }

    private function isAllowed(Attribute $attribute, ClassMethod $classMethod): bool
    {
        return self::IGNORE_DEPRECATIONS === $attribute->name->getLast()
            && $this->scopedToOwnPackage($attribute)
            && $this->assertsUserDeprecation($classMethod);
    }

    private function scopedToOwnPackage(Attribute $attribute): bool
    {
        $pattern = ($attribute->args[0]->value ?? null) instanceof String_ ? $attribute->args[0]->value->value : null;

        return null !== $pattern && str_contains($pattern, self::OWN_PACKAGE);
    }

    private function assertsUserDeprecation(ClassMethod $classMethod): bool
    {
        foreach ((new NodeFinder())->findInstanceOf($classMethod->stmts ?? [], MethodCall::class) as $methodCall) {
            if ($methodCall->name instanceof Identifier && \in_array($methodCall->name->toString(), self::ASSERTION_METHODS, true)) {
                return true;
            }
        }

        return false;
    }
}
