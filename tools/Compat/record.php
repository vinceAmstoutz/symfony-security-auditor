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

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\CompatAutoloader;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Recorder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\ScenarioCatalog;

$checkout = $argv[1] ?? '';
$release = $argv[2] ?? '';
$only = array_slice($argv, 3);

if (!is_file(sprintf('%s/vendor/autoload.php', $checkout)) || 1 !== preg_match('/^\d+\.\d+\.\d+$/', $release)) {
    fwrite(\STDERR, "Usage: php tools/Compat/record.php <checkout-with-vendor> <X.Y.Z> [scenario ...]\n");

    exit(2);
}

require sprintf('%s/vendor/autoload.php', $checkout);
require_once __DIR__.'/../../tests/Phpunit/Compat/CompatAutoloader.php';
CompatAutoloader::register();
error_reporting(\E_ALL & ~\E_DEPRECATED & ~\E_USER_DEPRECATED);

$fixtureRoot = sprintf('%s/tests/Phpunit/Compat/Fixture', dirname(__DIR__, 2));
$recorder = new Recorder(sprintf('%s/%s', $fixtureRoot, $release), $release);

if ([] !== $only) {
    $recorded = $recorder->record($only);
    foreach (array_intersect_key($recorder->unrecorded(), array_flip($only)) as $name => $reason) {
        fwrite(\STDERR, sprintf("Not recording %s: %s.\n", $name, $reason));
    }

    exit($recorded ? 0 : Recorder::REFUSED);
}

$previousRecordings = glob(sprintf('%s/*.*.*', $fixtureRoot), \GLOB_ONLYDIR);
(new Filesystem())->remove(false === $previousRecordings ? [] : $previousRecordings);

$failed = 0;
foreach (array_keys(ScenarioCatalog::all()) as $name) {
    $process = new Process([\PHP_BINARY, '-d', 'memory_limit=1G', __FILE__, $checkout, $release, $name]);
    $process->setTimeout(600);
    $process->run();
    $status = match ($process->getExitCode()) {
        0 => 'recorded',
        Recorder::REFUSED => 'refused ',
        default => 'FAILED  ',
    };
    $failed += 'FAILED  ' === $status ? 1 : 0;
    fwrite(\STDOUT, sprintf("%s %s\n", $status, $name));
    if ('recorded' !== $status) {
        fwrite(\STDERR, $process->getErrorOutput().$process->getOutput());
    }
}

exit(0 === $failed ? 0 : 1);
