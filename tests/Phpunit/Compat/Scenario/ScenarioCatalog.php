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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

use LogicException;

/**
 * Every scenario of the compatibility suite, by name.
 */
final readonly class ScenarioCatalog
{
    /**
     * @return array<string, Scenario>
     */
    public static function all(): array
    {
        $scenarios = [];
        foreach ([
            ...AuditRunScenarios::all(),
            ...OptionScenarios::all(),
            ...ReportScenarios::all(),
            ...ConfigFileScenarios::all(),
            ...StandaloneScenarios::all(),
            ...ApiScenarios::all(),
            ...McpScenarios::all(),
        ] as $scenario) {
            if (\array_key_exists($scenario->name, $scenarios)) {
                throw new LogicException(\sprintf('Two compatibility scenarios are named "%s".', $scenario->name));
            }

            $scenarios[$scenario->name] = $scenario;
        }

        ksort($scenarios);

        return $scenarios;
    }

    public static function get(string $name): Scenario
    {
        return self::all()[$name] ?? throw new LogicException(\sprintf('No compatibility scenario is named "%s".', $name));
    }
}
