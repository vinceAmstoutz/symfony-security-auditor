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

use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\CompatAutoloader;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Diff\DraftEntries;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Recordings;

require dirname(__DIR__, 2).'/vendor/autoload.php';
require_once dirname(__DIR__, 2).'/tests/Phpunit/Compat/CompatAutoloader.php';
CompatAutoloader::register();

if ('--scenario' === ($argv[1] ?? null)) {
    fwrite(\STDOUT, json_encode(DraftEntries::ofScenario($argv[2] ?? ''), \JSON_THROW_ON_ERROR));

    exit(0);
}

$parallel = 4;
$queue = Recordings::scenarios();
$running = [];
$draftEntries = new DraftEntries();
while ([] !== $queue || [] !== $running) {
    while (count($running) < $parallel && [] !== $queue) {
        $scenario = array_shift($queue);
        $running[$scenario] = new Process([\PHP_BINARY, '-d', 'memory_limit=1G', __FILE__, '--scenario', $scenario]);
        $running[$scenario]->setTimeout(600);
        $running[$scenario]->start();
    }

    foreach (array_filter($running, static fn (Process $process): bool => !$process->isRunning()) as $scenario => $process) {
        unset($running[$scenario]);
        if (!$draftEntries->add($scenario, $process->getOutput())) {
            fwrite(\STDERR, sprintf("%s could not be replayed:\n%s\n", $scenario, $process->getErrorOutput()));
        }
    }

    usleep(50_000);
}

fwrite(\STDERR, "Draft entries for tests/Phpunit/Compat/accepted-differences.php follow: give each a reason and its CHANGELOG bullet, widen a path only where every difference under it is the same change, and drop any that is a break to fix.\n");
fwrite(\STDOUT, $draftEntries->entries());
foreach ($draftEntries->stale() as $line) {
    fwrite(\STDERR, sprintf("No longer shows, take the scenario out of the entry: %s\n", $line));
}
