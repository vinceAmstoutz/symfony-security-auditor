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

#[AsTask(name: 'release:bump', description: 'Rewrite every release version pin (schema $id, GitHub Action uses: examples) to the given X.Y.Z tag')]
function releaseBump(string $version): void
{
    if (1 !== preg_match('/^\\d+\\.\\d+\\.\\d+$/', $version)) {
        io()->error(sprintf('"%s" is not a X.Y.Z version.', $version));

        exit(1);
    }

    $pinnedFiles = [
        'resources/schema.json' => '#(symfony-security-auditor/)\\d+\\.\\d+\\.\\d+(/resources/schema\\.json)#',
        'README.md' => '#(uses: vinceamstoutz/symfony-security-auditor@)\\d+\\.\\d+\\.\\d+#',
        'docs/ci.md' => '#(uses: vinceamstoutz/symfony-security-auditor@)\\d+\\.\\d+\\.\\d+#',
        'docs/versioning.md' => '#(uses: vinceamstoutz/symfony-security-auditor@)\\d+\\.\\d+\\.\\d+#',
    ];

    foreach ($pinnedFiles as $file => $pattern) {
        $content = file_get_contents($file);
        if (false === $content) {
            io()->error(sprintf('Could not read %s.', $file));

            exit(1);
        }

        $rewritten = preg_replace($pattern, '${1}'.$version.'${2}', $content, -1, $count);
        if (null === $rewritten || 0 === $count) {
            io()->error(sprintf('No version pin matched in %s — the pin list in castor.php is stale.', $file));

            exit(1);
        }

        file_put_contents($file, $rewritten);
        io()->writeln(sprintf('  <info>OK</info> %s (%d pin%s)', $file, $count, 1 === $count ? '' : 's'));
    }

    io()->success(sprintf('All version pins now point at %s.', $version));
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

#[AsTask(name: 'lint:docs', description: 'Check Markdown formatting only (fast pre-push check)')]
function lintDocs(): void
{
    $userFlag = sprintf('--user %d:%d', posix_getuid(), posix_getgid());

    io()->section('Prettier Markdown');
    run(sprintf(
        'docker run --rm %s -v "%s:/work" -w /work tmknom/prettier:3.6.2 --check "**/*.md"',
        $userFlag,
        getcwd(),
    ));

    io()->section('Markdown lint');
    run(sprintf(
        'docker run --rm %s -v "%s:/workdir" davidanson/markdownlint-cli2:latest',
        $userFlag,
        getcwd(),
    ));

    io()->success('Markdown looks good.');
}

function runCodeQualityTools(bool $fixMode = false): void
{
    $userFlag = sprintf('--user %d:%d', posix_getuid(), posix_getgid());

    io()->section('Prettier Markdown');
    run(sprintf(
        'docker run --rm %s -v "%s:/work" -w /work tmknom/prettier:3.6.2 --%s "**/*.md"',
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

    io()->section('Deptrac');
    run('docker compose exec php vendor/bin/deptrac analyse --no-progress');

    io()->section('Swiss Knife');
    run('docker compose exec php vendor/bin/swiss-knife check-commented-code src tests tools');
    run('docker compose exec php vendor/bin/swiss-knife check-conflicts src tests tools');

    io()->section('Install script tests');
    run('sh tests/Shell/install_script_test.sh');

    io()->section('PHPUnit');
    run('docker compose exec php vendor/bin/phpunit --coverage-clover=build/coverage/clover.xml');

    io()->section('Infection');
    run('docker compose exec php php -d memory_limit=1G bin/infection');

    io()->success($fixMode ? 'Fixing complete.' : 'Linting complete.');
}
