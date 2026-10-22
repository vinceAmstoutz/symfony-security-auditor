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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlRule;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AccessControlRuleMatcher;

final class AccessControlRuleMatcherTest extends TestCase
{
    private const string CATASTROPHIC_PATTERN = '^/(a+)+z0$';

    private const string CATASTROPHIC_ROUTE = '/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab0';

    /**
     * @param list<string>                $routeMethods
     * @param array<string, list<string>> $routeAccessMap
     * @param list<string>|false|null     $expectedRoles
     */
    #[DataProvider('routeCases')]
    public function test_it_finds_the_roles_of_the_rule_that_governs_the_route(?string $routePath, array $routeMethods, ?string $routeName, array $routeAccessMap, array|false|null $expectedRoles): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', $routePath, $routeMethods, true, [], false, false, $routeName);

        self::assertSame($expectedRoles, AccessControlRuleMatcher::rolesFor($routeAccessControl, $routeAccessMap));
    }

    /**
     * @param list<string>            $routeMethods
     * @param list<AccessControlRule> $accessControlRules
     */
    #[DataProvider('declaredRuleCases')]
    public function test_the_first_declared_rule_that_matches_some_requests_of_the_route_decides_whether_it_is_checked(array $routeMethods, array $accessControlRules, bool $checked): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/admin/users', $routeMethods, true, [], false, false, 'admin_users');

        self::assertSame($checked ? ['ROLE_MAP'] : null, AccessControlRuleMatcher::rolesFor($routeAccessControl, ['^/admin' => ['ROLE_MAP']], $accessControlRules));
    }

    /**
     * @return iterable<string, array{0: list<string>, 1: list<AccessControlRule>, 2: bool}>
     */
    public static function declaredRuleCases(): iterable
    {
        yield 'no declared rule' => [['GET'], [], true];
        yield 'a rule checking nothing for every method' => [['GET'], [new AccessControlRule('^/admin', [], false)], false];
        yield 'a rule checking nothing for the route method' => [['GET'], [new AccessControlRule('^/admin', ['GET'], false)], false];
        yield 'a rule checking nothing for the route method written in lower case' => [['get'], [new AccessControlRule('^/admin', ['GET'], false)], false];
        yield 'a rule checking nothing for another method' => [['GET'], [new AccessControlRule('^/admin', ['POST'], false)], true];
        yield 'a rule checking nothing for one of the route methods' => [['GET', 'POST'], [new AccessControlRule('^/admin', ['POST'], false)], false];
        yield 'a rule checking nothing for some methods of a route answering every method' => [[], [new AccessControlRule('^/admin', ['GET'], false)], false];
        yield 'a rule checking nothing for another path' => [['GET'], [new AccessControlRule('^/other', [], false)], true];
        yield 'a rule checking nothing for the route name' => [['GET'], [new AccessControlRule('route: admin_users', [], false)], false];
        yield 'a rule checking nothing for another route name' => [['GET'], [new AccessControlRule('route: admin_export', [], false)], true];
        yield 'a checking rule for every method, then one checking nothing' => [['GET'], [new AccessControlRule('^/admin', [], true), new AccessControlRule('^/', [], false)], true];
        yield 'a checking rule for the route methods, then one checking nothing' => [['GET', 'POST'], [new AccessControlRule('^/admin', ['GET', 'POST', 'PUT'], true), new AccessControlRule('^/', [], false)], true];
        yield 'a checking rule for some route methods, then one checking nothing' => [['GET', 'POST'], [new AccessControlRule('^/admin', ['GET'], true), new AccessControlRule('^/', [], false)], false];
        yield 'a checking rule for some methods of a route answering every method, then one checking nothing' => [[], [new AccessControlRule('^/admin', ['GET'], true), new AccessControlRule('^/', [], false)], false];
        yield 'a checking rule for another method, then one checking nothing' => [['GET'], [new AccessControlRule('^/admin', ['POST'], true), new AccessControlRule('^/', [], false)], false];
        yield 'a checking rule of another path, then one checking nothing' => [['GET'], [new AccessControlRule('^/other', [], true), new AccessControlRule('^/', [], false)], false];
    }

    /**
     * @param list<string>            $routeMethods
     * @param list<AccessControlRule> $accessControlRules
     * @param list<string>|false|null $expectedRoles
     */
    #[DataProvider('undecidableDeclaredRuleCases')]
    public function test_a_declared_rule_whose_pattern_cannot_be_decided_leaves_the_route_undetermined_only_when_it_would_decide_it(array $routeMethods, array $accessControlRules, array|false|null $expectedRoles): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', self::CATASTROPHIC_ROUTE, $routeMethods, true, [], false, false);

        self::assertSame($expectedRoles, AccessControlRuleMatcher::rolesFor($routeAccessControl, ['^/a' => ['ROLE_A']], $accessControlRules));
    }

    /**
     * @return iterable<string, array{0: list<string>, 1: list<AccessControlRule>, 2: list<string>|false|null}>
     */
    public static function undecidableDeclaredRuleCases(): iterable
    {
        yield 'a rule checking nothing' => [['GET'], [new AccessControlRule(self::CATASTROPHIC_PATTERN, [], false), new AccessControlRule('^/a', [], true)], false];
        yield 'a checking rule for every request of the route' => [['GET'], [new AccessControlRule(self::CATASTROPHIC_PATTERN, [], true), new AccessControlRule('^/a', [], true)], false];
        yield 'a checking rule for some requests of the route, then one checking nothing' => [['GET', 'POST'], [new AccessControlRule(self::CATASTROPHIC_PATTERN, ['GET'], true), new AccessControlRule('^/a', [], false)], null];
        yield 'a rule checking nothing for another method, then a checking rule' => [['GET'], [new AccessControlRule(self::CATASTROPHIC_PATTERN, ['POST'], false), new AccessControlRule('^/a', [], true)], ['ROLE_A']];
        yield 'a rule checking nothing after the checking rule that settles the route' => [['GET'], [new AccessControlRule('^/a', [], true), new AccessControlRule(self::CATASTROPHIC_PATTERN, [], false)], ['ROLE_A']];
    }

    /**
     * @return iterable<string, array{0: ?string, 1: list<string>, 2: ?string, 3: array<string, list<string>>, 4: list<string>|false|null}>
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
        yield 'route name rule listed before a broader path rule governs the route' => ['/admin/dashboard', ['GET'], 'admin_dashboard', ['route: admin_dashboard' => ['PUBLIC_ACCESS'], '^/admin' => ['ROLE_ADMIN']], ['PUBLIC_ACCESS']];
        yield 'route name rule skipped on a method mismatch leaves the route to the next path rule' => ['/admin/dashboard', ['GET'], 'admin_dashboard', ['route: admin_dashboard' => ['PUBLIC_ACCESS', 'methods: POST'], '^/admin' => ['ROLE_ADMIN']], ['ROLE_ADMIN']];
        yield 'route name rule of another route leaves the route to the next path rule' => ['/admin/dashboard', ['GET'], 'admin_dashboard', ['route: admin_dashboard_export' => ['PUBLIC_ACCESS'], '^/admin' => ['ROLE_ADMIN']], ['ROLE_ADMIN']];
        yield 'path rule listed before a route name rule is skipped for a route without a path' => [null, ['GET'], 'admin_dashboard', ['^/admin' => ['ROLE_ADMIN'], 'route: admin_dashboard' => ['ROLE_NAME']], ['ROLE_NAME']];
        yield 'pattern holding a delimiter candidate' => ['/a#b', ['GET'], null, ['^/a#b$' => ['ROLE_HASH']], ['ROLE_HASH']];
        yield 'pattern holding every delimiter candidate' => ['/#~!%@', ['GET'], null, ['#~!%@' => ['ROLE_ALL']], null];
        yield 'pattern that does not compile matches nothing' => ['/admin', ['GET'], null, ['^/(admin' => ['ROLE_BROKEN']], null];
        yield 'pattern that cannot be decided within the bound leaves the route undetermined' => [self::CATASTROPHIC_ROUTE, ['GET'], null, [self::CATASTROPHIC_PATTERN => ['ROLE_X']], false];
        yield 'pattern that cannot be decided listed before a matching rule leaves the route undetermined' => [self::CATASTROPHIC_ROUTE, ['GET'], null, [self::CATASTROPHIC_PATTERN => ['ROLE_X'], '^/a' => ['ROLE_A']], false];
        yield 'pattern that cannot be decided listed after the governing rule is never reached' => [self::CATASTROPHIC_ROUTE, ['GET'], null, ['^/a' => ['ROLE_A'], self::CATASTROPHIC_PATTERN => ['ROLE_X']], ['ROLE_A']];
        yield 'pattern that cannot be decided is not evaluated for a rule skipped on a method mismatch' => [self::CATASTROPHIC_ROUTE, ['GET'], null, [self::CATASTROPHIC_PATTERN => ['ROLE_X', 'methods: POST'], '^/a' => ['ROLE_A']], ['ROLE_A']];
        yield 'pattern decided within ten thousand backtracking steps' => [str_repeat('/a', 9_997).'/', ['GET'], null, ['(*NO_JIT)^(?:/a)*$' => ['ROLE_X']], null];
        yield 'pattern needing one backtracking step past ten thousand' => [str_repeat('/a', 9_998).'/', ['GET'], null, ['(*NO_JIT)^(?:/a)*$' => ['ROLE_X']], false];
    }

    public function test_each_route_walked_through_the_rules_at_once_gets_the_roles_of_the_rule_that_governs_it_alone(): void
    {
        $routeAccessControls = [
            3 => new RouteAccessControl('src/Controller/X.php', 'users', '/admin/users', ['GET'], true, [], false, false, 'admin_users'),
            5 => new RouteAccessControl('src/Controller/X.php', 'open', '/open', ['get'], true, [], false, false, 'open'),
            7 => new RouteAccessControl('src/Controller/X.php', 'export', '/export', ['GET', 'POST'], true, [], false, false, 'export'),
            9 => new RouteAccessControl('src/Controller/X.php', 'named', null, ['GET'], true, [], false, false, 'admin_index'),
            11 => new RouteAccessControl('src/Controller/X.php', 'slow', self::CATASTROPHIC_ROUTE, ['GET'], true, [], false, false, 'slow'),
            13 => new RouteAccessControl('src/Controller/X.php', 'login', '/login', ['GET'], true, [], false, false, 'login'),
        ];
        $accessControlRules = [
            new AccessControlRule(self::CATASTROPHIC_PATTERN, [], false),
            new AccessControlRule('^/login', ['POST'], false),
            new AccessControlRule('^/admin', [], true),
            new AccessControlRule('^/export', ['GET'], true),
            new AccessControlRule('^/(open|admin|export)', ['GET'], false),
        ];
        $routeAccessMap = ['^/admin' => ['ROLE_ADMIN'], 'route: admin_index' => ['ROLE_NAME'], '^/login' => ['ROLE_LOGIN', 'methods: POST'], '^/' => ['ROLE_ANY']];

        self::assertSame(
            [3 => ['ROLE_ADMIN'], 5 => null, 7 => null, 9 => ['ROLE_NAME'], 11 => false, 13 => ['ROLE_ANY']],
            AccessControlRuleMatcher::rolesForEach($routeAccessControls, $routeAccessMap, $accessControlRules),
        );
    }

    public function test_the_backtrack_limit_in_place_before_matching_is_back_afterwards(): void
    {
        $previousLimit = \ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '777777');

        try {
            AccessControlRuleMatcher::rolesFor(new RouteAccessControl('src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false), ['^/admin' => ['ROLE_ADMIN']]);
            $limitAfterMatching = \ini_get('pcre.backtrack_limit');
        } finally {
            ini_set('pcre.backtrack_limit', false === $previousLimit ? '1000000' : $previousLimit);
        }

        self::assertSame('777777', $limitAfterMatching);
    }
}
