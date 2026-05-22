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

use Castor\Attribute\AsTask;

use function Castor\io;
use function Castor\run;

#[AsTask(name: 'up', description: 'Install dependencies')]
function setup(): void
{
    run('docker compose up --wait');
}

#[AsTask(name: 'down', description: 'Stop all containers and remove orphans')]
function down(): void
{
    run('docker compose down --remove-orphans');
}

#[AsTask(name: 'lint', description: 'Check code style and analyze code')]
function lint(): void
{
    runCodeQualityTools();
}

#[AsTask(name: 'lint:fix', description: 'Fix code style and apply refactorings')]
function fix(): void
{
    runCodeQualityTools(fixMode: true);
}

function runCodeQualityTools(bool $fixMode = false): void
{
    $userFlag = sprintf('--user %d:%d', posix_getuid(), posix_getgid());

    io()->section('Prettier Markdown');
    run(sprintf(
        'docker run --rm %s -v "%s:/work" -w /work tmknom/prettier:latest --%s "**/*.md"',
        $userFlag,
        getcwd(),
        $fixMode ? 'write' : 'check',
    ));

    io()->section('Markdown lint');
    run(sprintf(
        'docker run --rm %s -v "%s:/workdir" davidanson/markdownlint-cli2:latest%s',
        $userFlag,
        getcwd(),
        $fixMode ? ' --fix' : '',
    ));

    io()->section('Composer Normalize');
    run('docker compose exec php composer normalize'.($fixMode ? '' : ' --dry-run'));

    io()->section('PHP CS Fixer');
    run('docker compose exec php vendor/bin/php-cs-fixer fix'.($fixMode ? '' : ' --dry-run --diff'));

    io()->section('Rector');
    run('docker compose exec php vendor/bin/rector process'.($fixMode ? '' : ' --dry-run'));

    io()->section('PHPStan');
    run('docker compose exec php vendor/bin/phpstan analyse --memory-limit=500M');

    io()->section('PHPUnit');
    run('docker compose exec php vendor/bin/phpunit');

    io()->section('Infection');
    run('docker compose exec php bin/infection');

    io()->success($fixMode ? 'Fixing complete.' : 'Linting complete.');
}
