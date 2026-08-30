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
 * Extracts the entrypoint access map and the perimeter rules from a security
 * configuration file's raw content (Symfony: `security.yaml`'s `access_control`
 * and `firewalls`). Implementations must degrade gracefully: content that is not
 * parseable security configuration yields empty results, never an exception — a
 * broken config file must not abort the audit.
 */
interface AccessControlConfigParserInterface
{
    /**
     * @return array<string, list<string>> route path pattern (or `route: <name>`)
     *                                     mapped to its access requirements —
     *                                     roles plus `allow_if: …`, `methods: …`,
     *                                     `ips: …`, and `requires_channel: …`
     *                                     constraints when present
     */
    public function parseEntrypointAccessMap(string $configContent): array;

    /**
     * @return list<string> one entry per perimeter rule: its path pattern
     *                      (falling back to the rule's name), with `security:
     *                      false` and `stateless` flags appended in parentheses
     */
    public function parsePerimeterRules(string $configContent): array;
}
