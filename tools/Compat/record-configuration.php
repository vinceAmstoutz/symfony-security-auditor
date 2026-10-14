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

use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Configuration\ConfigurationSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\FixtureSeal;

$checkout = $argv[1] ?? '';
$release = $argv[2] ?? '';

if (!is_file(sprintf('%s/vendor/autoload.php', $checkout)) || 1 !== preg_match('/^\d+\.\d+\.\d+$/', $release)) {
    fwrite(\STDERR, "Usage: php tools/Compat/record-configuration.php <checkout-with-vendor> <X.Y.Z>\n");

    exit(2);
}

require sprintf('%s/vendor/autoload.php', $checkout);

$compatNamespace = 'VinceAmstoutz\\SymfonySecurityAuditor\\Tests\\Compat\\';
$compatDirectory = dirname(__DIR__, 2).'/tests/Phpunit/Compat';
$snapshotDirectory = $compatDirectory.'/Configuration';
spl_autoload_register(static function (string $class) use ($compatNamespace, $compatDirectory): void {
    if (str_starts_with($class, $compatNamespace)) {
        require_once sprintf('%s/%s.php', $compatDirectory, str_replace('\\', '/', substr($class, strlen($compatNamespace))));
    }
}, true, true);
error_reporting(\E_ALL & ~\E_DEPRECATED & ~\E_USER_DEPRECATED);

$fixture = sprintf('%s/Fixture/%s.json', $snapshotDirectory, $release);
$previousRecordings = glob(sprintf('%s/Fixture/*.*.*.json', $snapshotDirectory));
foreach (false === $previousRecordings ? [] : $previousRecordings as $previous) {
    unlink($previous);
}

if (!is_dir(dirname($fixture))) {
    mkdir(dirname($fixture), 0o777, true);
}

file_put_contents($fixture, json_encode(FixtureSeal::sealed(['release' => $release, ...ConfigurationSnapshot::all()]), \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_PRESERVE_ZERO_FRACTION | \JSON_THROW_ON_ERROR)."\n");
fwrite(\STDOUT, sprintf("Recorded the configuration of %s into %s\n", $release, $fixture));
