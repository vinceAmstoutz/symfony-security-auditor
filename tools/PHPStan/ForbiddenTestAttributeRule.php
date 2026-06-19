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
use PhpParser\Node\Attribute;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\ShouldNotHappenException;

/**
 * Bans test attributes that opt out of a quality gate instead of fixing the
 * underlying test (mirrors the no-silence policy for PHPStan/Infection).
 *
 * @implements Rule<Attribute>
 */
final readonly class ForbiddenTestAttributeRule implements Rule
{
    /**
     * @var array<string, string>
     */
    private const array FORBIDDEN = [
        'AllowMockObjectsWithoutExpectations' => 'use a stub (createStub) for a collaborator with no configured expectations',
        'DoesNotPerformAssertions' => 'assert a real outcome instead of declaring the test asserts nothing',
        'IgnoreDeprecations' => 'resolve the deprecation rather than ignoring it',
        'WithoutErrorHandler' => 'keep the error handler so failOnWarning/failOnNotice still apply',
    ];

    public function getNodeType(): string
    {
        return Attribute::class;
    }

    /**
     * @return list<IdentifierRuleError>
     *
     * @throws ShouldNotHappenException
     */
    public function processNode(Node $node, Scope $scope): array
    {
        $name = $node->name->getLast();
        if (!\array_key_exists($name, self::FORBIDDEN)) {
            return [];
        }

        return [
            RuleErrorBuilder::message(\sprintf('Attribute #[%s] is forbidden — %s.', $name, self::FORBIDDEN[$name]))
                ->identifier('ssa.forbiddenTestAttribute')
                ->build(),
        ];
    }
}
