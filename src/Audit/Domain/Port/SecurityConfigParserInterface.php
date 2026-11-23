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

/**
 * Extracts the access-control map and firewall rules of a security
 * configuration file's content. Implementations MUST return empty results for
 * content they cannot parse, never throw.
 */
interface SecurityConfigParserInterface
{
    /**
     * @return array<string, list<string>> route path pattern (or `route: <name>`)
     *                                     mapped to its access requirements:
     *                                     roles plus `allow_if: …`, `methods: …`,
     *                                     `ips: …` and `requires_channel: …`
     *                                     constraints when present
     */
    public function parseAccessControl(string $configContent): array;

    /**
     * @return list<string> one entry per firewall: its `pattern` (falling back
     *                      to the firewall name), with `security: false` and
     *                      `stateless` flags appended in parentheses
     */
    public function parseFirewallRules(string $configContent): array;
}
