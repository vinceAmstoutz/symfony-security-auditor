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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AccessControlRuleMatcher;

final class AccessControlRuleMatcherTest extends TestCase
{
    private const string BACKTRACKING_RULE = '^/(?:(a+)+z|a+)$';

    /**
     * @param list<string>                $routeMethods
     * @param array<string, list<string>> $routeAccessMap
     * @param list<string>|null           $expectedRoles
     */
    #[DataProvider('routeCases')]
    public function test_it_finds_the_roles_of_the_rule_that_governs_the_route(?string $routePath, array $routeMethods, ?string $routeName, array $routeAccessMap, ?array $expectedRoles): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', $routePath, $routeMethods, true, [], false, false, $routeName);

        self::assertSame($expectedRoles, AccessControlRuleMatcher::rolesFor($routeAccessControl, $routeAccessMap));
    }

    /**
     * @return iterable<string, array{0: ?string, 1: list<string>, 2: ?string, 3: array<string, list<string>>, 4: list<string>|null}>
     */
    public static function routeCases(): iterable
    {
        yield 'path pattern matches' => ['/admin/users', ['GET'], null, ['^/admin' => ['ROLE_ADMIN']], ['ROLE_ADMIN']];
        yield 'no pattern matches' => ['/open', ['GET'], null, ['^/admin' => ['ROLE_ADMIN']], null];
        yield 'path rule wins over route name rule' => ['/admin', ['GET'], 'admin_index', ['^/admin' => ['ROLE_PATH'], 'route: admin_index' => ['ROLE_NAME']], ['ROLE_PATH']];
        yield 'route name rule used when no path matches' => ['/open', ['GET'], 'admin_index', ['route: admin_index' => ['ROLE_NAME']], ['ROLE_NAME']];
        yield 'route without path falls back to its name' => [null, ['GET'], 'admin_index', ['route: admin_index' => ['ROLE_NAME']], ['ROLE_NAME']];
        yield 'route without path nor name matches nothing' => [null, ['GET'], null, ['route: ' => ['ROLE_EMPTY_NAME'], '^/admin' => ['ROLE_ADMIN']], null];
        yield 'route name rule skipped on a method mismatch' => ['/open', ['GET'], 'admin_index', ['route: admin_index' => ['ROLE_NAME', 'methods: POST']], null];
        yield 'method mismatch moves on to the next rule' => ['/admin', ['GET'], null, ['^/admin' => ['ROLE_A', 'methods: POST'], '^/adm' => ['ROLE_B']], ['ROLE_B']];
        yield 'route without declared methods is not covered by a method-restricted rule' => ['/admin', [], null, ['^/admin' => ['ROLE_A', 'methods: GET']], null];
        yield 'any or-alternative may cover the methods' => ['/x', ['POST'], null, ['^/x' => ['methods: GET', 'or: methods: POST']], ['methods: GET', 'or: methods: POST']];
        yield 'route methods are compared case-insensitively' => ['/admin', ['get'], null, ['^/admin' => ['ROLE_ADMIN', 'methods: GET']], ['ROLE_ADMIN', 'methods: GET']];
        yield 'pattern holding a delimiter candidate' => ['/a#b', ['GET'], null, ['^/a#b$' => ['ROLE_HASH']], ['ROLE_HASH']];
        yield 'pattern holding every delimiter candidate' => ['/#~!%@', ['GET'], null, ['#~!%@' => ['ROLE_ALL']], null];
        yield 'rule that backtracks within the match bound still governs the route' => ['/'.str_repeat('a', 9), ['GET'], null, [self::BACKTRACKING_RULE => ['ROLE_SLOW']], ['ROLE_SLOW']];
        yield 'rule that backtracks beyond the match bound governs nothing' => ['/'.str_repeat('a', 17), ['GET'], null, [self::BACKTRACKING_RULE => ['ROLE_SLOW']], null];
        yield 'rule that backtracks beyond the match bound leaves the route to the next rule' => ['/'.str_repeat('a', 17), ['GET'], null, [self::BACKTRACKING_RULE => ['ROLE_SLOW'], '^/a' => ['ROLE_NEXT']], ['ROLE_NEXT']];
    }

    public function test_the_backtrack_limit_in_place_before_matching_is_back_afterwards(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/'.str_repeat('a', 17), ['GET'], true, [], false, false);
        $previousLimit = ini_set('pcre.backtrack_limit', '123456');

        try {
            AccessControlRuleMatcher::rolesFor($routeAccessControl, [self::BACKTRACKING_RULE => ['ROLE_SLOW']]);
            $limitAfterwards = \ini_get('pcre.backtrack_limit');
        } finally {
            ini_set('pcre.backtrack_limit', (string) $previousLimit);
        }

        self::assertSame('123456', $limitAfterwards);
    }
}
