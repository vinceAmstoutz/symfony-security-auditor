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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlRule;

/**
 * Opt-in extension of {@see SecurityConfigParserInterface} for parsers that
 * also give the `access_control` rules in the order the configuration
 * declares them, those that check nothing included, since the application
 * applies the first rule that matches a request. `MappingStage` checks
 * `instanceof RuleOrderAwareSecurityConfigParserInterface`; without it, a
 * route is labelled from the access-control map alone.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface RuleOrderAwareSecurityConfigParserInterface extends SecurityConfigParserInterface
{
    /**
     * @return list<AccessControlRule>
     */
    public function parseAccessControlRules(string $configContent): array;
}
