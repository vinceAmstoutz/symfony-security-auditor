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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner;

use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\ApplicationTester;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Step;

/**
 * Runs one command the way a terminal user does: through the application,
 * which renders an uncaught exception and turns it into exit code 1, from the
 * step's working directory, answering its prompts when the step says what to
 * type.
 */
final readonly class ConsoleTester
{
    public static function run(Application $application, Step $step, Workspace $workspace): ConsoleRun
    {
        $application->setAutoExit(false);
        $applicationTester = new ApplicationTester($application);
        $applicationTester->setInputs($step->answers);

        $exitCode = $applicationTester->run(['command' => $step->command, ...self::expandedInput($step, $workspace)], [
            'interactive' => [] !== $step->answers,
            'decorated' => false,
            'capture_stderr_separately' => true,
        ]);

        return new ConsoleRun($exitCode, $applicationTester->getDisplay(), $applicationTester->getErrorOutput());
    }

    public static function enter(Step $step, Workspace $workspace): string
    {
        $workingDirectory = $workspace->resolve($step->workingDirectory);
        if (!is_dir($workingDirectory)) {
            mkdir($workingDirectory, 0o777, true);
        }

        chdir($workingDirectory);

        return $workingDirectory;
    }

    /**
     * @return array<string, bool|int|string|list<string>|null>
     */
    private static function expandedInput(Step $step, Workspace $workspace): array
    {
        $input = [];
        foreach ($step->input as $name => $value) {
            $input[$name] = match (true) {
                \is_string($value) => $workspace->confined($workspace->expand($value)),
                \is_array($value) => array_map(static fn (string $item): string => $workspace->confined($workspace->expand($item)), $value),
                default => $value,
            };
        }

        return $input;
    }
}
