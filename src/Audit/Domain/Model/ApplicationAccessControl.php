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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * The `access_control` rules and firewalls an application of a monorepo
 * declares in its own configuration; they govern the routes of that
 * application only.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ApplicationAccessControl
{
    /**
     * @param array<string, list<string>> $routeAccessMap
     * @param list<string>                $firewallRules
     * @param list<AccessControlRule>     $accessControlRules the rules in the order the application declares them, when the parser gave them
     */
    public function __construct(
        public array $routeAccessMap,
        public array $firewallRules,
        public array $accessControlRules = [],
    ) {}
}
