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
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\EvalBaseline;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\EvalReport;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\EvalScorer;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\GroundTruthManifest;

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

#[AsTask(name: 'eval', description: 'Audit a ground-truth fixture and score detection precision/recall against its manifest')]
function evaluate(
    string $target = 'examples/vulnerable-app',
    string $groundTruth = 'examples/vulnerable-app/ground-truth.json',
    float $minPrecision = 0.0,
    float $minRecall = 0.0,
    string $baseline = 'examples/vulnerable-app/eval-baseline.json',
    bool $writeBaseline = false,
): void {
    $reportPath = sprintf('%s/ssa-eval-%s.json', sys_get_temp_dir(), bin2hex(random_bytes(4)));

    io()->section('Running the auditor against the fixture (uses real LLM calls)');
    run(sprintf('docker compose exec php bin/console audit:run %s --format=json --output=%s', $target, $reportPath));

    $manifest = GroundTruthManifest::fromFile($groundTruth);
    $evalReport = (new EvalScorer())->score($manifest, actualFindingsFromReport($reportPath));

    printEvalReport($evalReport);

    if (!$evalReport->meetsThresholds($minPrecision, $minRecall)) {
        io()->error(sprintf('Below thresholds: precision >= %.2f and recall >= %.2f required.', $minPrecision, $minRecall));

        exit(1);
    }

    if ($writeBaseline) {
        writeEvalBaseline($baseline, $evalReport);

        return;
    }

    assertNoEvalDrift($baseline, $evalReport);

    io()->success('Detection quality meets the configured thresholds.');
}

function writeEvalBaseline(string $baseline, EvalReport $evalReport): void
{
    if (false === file_put_contents($baseline, EvalBaseline::fromReport($evalReport)->toJson())) {
        io()->error(sprintf('Could not write the eval baseline to %s. Check the path exists and is writable.', $baseline));

        exit(1);
    }

    io()->success(sprintf('Recorded this run as the eval baseline in %s. Commit it alongside the change it certifies.', $baseline));
}

/**
 * Detection quality is the only gate that proves a wide no-behaviour-change
 * refactor still finds the same vulnerabilities — coverage and MSI only prove
 * the code still executes. A missing baseline is reported, not ignored.
 */
function assertNoEvalDrift(string $baseline, EvalReport $evalReport): void
{
    if (!is_file($baseline)) {
        io()->warning(sprintf('No eval baseline at %s, so detection quality was not compared. Record one with `bin/castor eval --write-baseline`.', $baseline));

        return;
    }

    $drift = EvalBaseline::fromFile($baseline)->driftAgainst($evalReport);
    if ([] === $drift) {
        io()->writeln(sprintf('  <info>OK</info> Detection quality matches the baseline in %s.', $baseline));

        return;
    }

    io()->error(sprintf('Detection quality drifted from the baseline in %s:', $baseline));
    io()->listing($drift);

    exit(1);
}

/**
 * @return list<array{file: string, type: string}>
 */
function actualFindingsFromReport(string $reportPath): array
{
    $decoded = json_decode((string) file_get_contents($reportPath), true, flags: \JSON_THROW_ON_ERROR);
    $vulnerabilities = is_array($decoded) ? ($decoded['vulnerabilities'] ?? []) : [];

    $findings = [];
    foreach (is_array($vulnerabilities) ? $vulnerabilities : [] as $vulnerability) {
        if (is_array($vulnerability) && is_string($vulnerability['file'] ?? null) && is_string($vulnerability['type'] ?? null)) {
            $findings[] = ['file' => $vulnerability['file'], 'type' => $vulnerability['type']];
        }
    }

    return $findings;
}

function printEvalReport(EvalReport $evalReport): void
{
    $rows = [];
    foreach ([$evalReport->overall, ...$evalReport->perClass] as $classScore) {
        $rows[] = [
            $classScore->type,
            sprintf('%.0f%%', $classScore->precision() * 100),
            sprintf('%.0f%%', $classScore->recall() * 100),
            sprintf('%.2f', $classScore->f1()),
            sprintf('%d / %d / %d', $classScore->truePositives, $classScore->falsePositives, $classScore->falseNegatives),
        ];
    }

    io()->table(['Class', 'Precision', 'Recall', 'F1', 'TP / FP / FN'], $rows);
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
    run('docker compose exec php composer normalize'.($fixMode ? '' : ' --dry-run').' packages/core/composer.json');

    io()->section('PHP CS Fixer');
    run('docker compose exec php vendor/bin/php-cs-fixer fix'.($fixMode ? '' : ' --dry-run --diff'));

    io()->section('Rector');
    run('docker compose exec php vendor/bin/rector process'.($fixMode ? '' : ' --dry-run'));

    io()->section('PHPStan');
    run('docker compose exec php vendor/bin/phpstan analyse --memory-limit=500M');

    io()->section('Deptrac');
    run('docker compose exec php vendor/bin/deptrac analyse --no-progress');

    io()->section('Swiss Knife');
    run('docker compose exec php vendor/bin/swiss-knife check-commented-code packages/core/src src tests tools');
    run('docker compose exec php vendor/bin/swiss-knife check-conflicts packages/core/src src tests tools');

    io()->section('Install script tests');
    run('sh tests/Shell/install_script_test.sh');

    io()->section('PHPUnit');
    run('docker compose exec php vendor/bin/phpunit --coverage-clover=build/coverage/clover.xml --coverage-xml=build/coverage/coverage-xml --log-junit=build/coverage/junit.xml');

    io()->section('Infection');
    run('docker compose exec php php -d memory_limit=2G bin/infection --configuration=infection.json5 --threads=max --coverage=build/coverage --skip-initial-tests --min-msi=100 --min-covered-msi=100');

    io()->success($fixMode ? 'Fixing complete.' : 'Linting complete.');
}
