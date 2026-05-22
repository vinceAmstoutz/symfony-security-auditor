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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AdvisoryDatabaseInterface;

/**
 * Bridges the security advisory database to the LLM's tool-calling protocol.
 * The LLM passes a Composer package name and an installed version; the database
 * adapter returns matching CVE entries (or an "no advisories found" message).
 */
final readonly class LookupAdvisoryTool implements ToolInterface
{
    public function __construct(private AdvisoryDatabaseInterface $advisoryDatabase) {}

    public function definition(): ToolDefinition
    {
        return new ToolDefinition(
            name: 'lookup_advisory',
            description: 'Look up known security advisories (CVEs) affecting a Composer package at the installed version. Use this when you spot a vendored library in composer.json or composer.lock to confirm whether a known vulnerability is present.',
            parametersSchema: [
                'type' => 'object',
                'properties' => [
                    'package' => [
                        'type' => 'string',
                        'description' => 'Composer package name, e.g. symfony/http-foundation',
                    ],
                    'version' => [
                        'type' => 'string',
                        'description' => 'Installed version, e.g. 6.4.2',
                    ],
                ],
                'required' => ['package', 'version'],
            ],
        );
    }

    public function execute(array $arguments): string
    {
        $package = $arguments['package'] ?? null;
        $version = $arguments['version'] ?? null;

        if (!\is_string($package) || '' === $package) {
            return 'Error: missing or empty "package" argument.';
        }

        if (!\is_string($version) || '' === $version) {
            return 'Error: missing or empty "version" argument.';
        }

        $entries = $this->advisoryDatabase->lookup($package, $version);

        if ([] === $entries) {
            return \sprintf('No advisories found for %s @ %s.', $package, $version);
        }

        $lines = [];
        foreach ($entries as $entry) {
            $lines[] = \sprintf(
                "%s — %s\nSummary: %s\nAffected: %s\nLink: %s",
                $entry['cve'] ?? '(no CVE)',
                $entry['title'],
                $entry['summary'],
                $entry['affected_versions'],
                $entry['link'] ?? '(no link)',
            );
        }

        return implode("\n\n", $lines);
    }
}
