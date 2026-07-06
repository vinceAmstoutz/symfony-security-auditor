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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture\MeasuringTokenEstimator;

final class EstimateAuditCostUseCaseTest extends TestCase
{
    private string $tmpDir;

    public function test_emits_zero_tokens_when_no_files_are_scanned(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 99),
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        $byRole = $auditReport->cost()->byRole();
        self::assertSame(0, $byRole['attacker']['input_tokens']);
        self::assertSame(0, $byRole['attacker']['output_tokens']);
    }

    public function test_per_file_token_estimates_are_summed_via_addition(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [
                $this->makeProjectFile('a.php', '<?php // ten ch'),     // 15 chars
                $this->makeProjectFile('b.php', '<?php /* 1 */'),       // 13 chars
            ],
            'tokenEstimator' => $this->lengthEchoingEstimator(),
            'maxIterations' => 1,
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(28, $auditReport->cost()->byRole()['attacker']['input_tokens'], 'per-file estimates must be summed (15+13), not overwritten by the last file');
    }

    public function test_input_token_estimate_scales_with_max_iterations(): void
    {
        // Pins: `* maxIterations` (vs `/`). With perRoundTokens=10 and maxIterations=5,
        // expected attacker = 50; with division mutation, would be 2.
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 10),
            'maxIterations' => 5,
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(50, $auditReport->cost()->byRole()['attacker']['input_tokens']);
    }

    public function test_output_token_estimate_uses_ceil_of_output_ratio(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 100),
            'maxIterations' => 1,
            'outputRatio' => 0.155,
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        $byRole = $auditReport->cost()->byRole();
        self::assertSame(100, $byRole['attacker']['input_tokens']);
        self::assertSame(16, $byRole['attacker']['output_tokens']);
    }

    public function test_output_token_estimate_uses_ceil_not_floor(): void
    {
        // 100 * 0.21 = 21.0 exactly — floor=21, ceil=21, round=21. Useless to distinguish.
        // Try 100 * 0.234 = 23.4 → ceil=24, floor=23, round=23. Picks ceil distinctly.
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 100),
            'maxIterations' => 1,
            'outputRatio' => 0.234,
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(24, $auditReport->cost()->byRole()['attacker']['output_tokens']);
    }

    public function test_full_file_content_length_reaches_the_estimator(): void
    {
        $measuringTokenEstimator = $this->measuringEstimator();
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', str_repeat('a', 1000))],
            'tokenEstimator' => $measuringTokenEstimator,
        ]);

        $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(1000, $measuringTokenEstimator->lastInputLength);
    }

    public function test_logs_starting_message_with_project_path_context(): void
    {
        $logCalls = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$logCalls): void {
                $logCalls[] = [$msg, $ctx];
            },
        );

        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 1),
            'logger' => $logger,
        ]);

        $estimateAuditCostUseCase->execute($this->tmpDir);

        $startLogs = array_values(array_filter(
            $logCalls,
            static fn (array $entry): bool => 'Estimating audit cost (dry-run)' === $entry[0],
        ));
        self::assertCount(1, $startLogs);
        self::assertSame($this->tmpDir, $startLogs[0][1]['project']);
    }

    public function test_logs_ready_message_with_estimate_breakdown(): void
    {
        $logCalls = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$logCalls): void {
                $logCalls[] = [$msg, $ctx];
            },
        );

        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [
                $this->makeProjectFile('a.php', 'aaa'),
                $this->makeProjectFile('b.php', 'bbb'),
            ],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 100),
            'logger' => $logger,
            'maxIterations' => 2,
            'outputRatio' => 0.5,
        ]);

        $estimateAuditCostUseCase->execute($this->tmpDir);

        $readyLogs = array_values(array_filter(
            $logCalls,
            static fn (array $entry): bool => 'Dry-run estimate ready' === $entry[0],
        ));
        self::assertCount(1, $readyLogs);
        $context = $readyLogs[0][1];
        self::assertSame(2, $context['files']);
        // per-round input = 100 (file a) + 100 (file b) = 200; attacker = 200 * 2 = 400,
        // reviewer = ceil(400 * 0.20) = 80, total = 480
        self::assertSame(480, $context['input_tokens']);
        // attacker_out = ceil(400 * 0.5) = 200, reviewer_out = ceil(80 * 0.5) = 40, total = 240
        self::assertSame(240, $context['output_tokens']);
        self::assertSame(0.0, $context['estimated_cost_usd']);
        self::assertSame(0.0, $context['attacker_cost_usd']);
        self::assertSame(0.0, $context['reviewer_cost_usd']);
    }

    public function test_dry_run_emits_attacker_and_reviewer_breakdown(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 100),
            'primaryModel' => 'claude-opus-4-7',
            'maxIterations' => 1,
            'outputRatio' => 0.5,
            'reviewerModel' => 'claude-haiku-4-5',
            'reviewerInputRatio' => 0.25,
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        $byRole = $auditReport->cost()->byRole();
        self::assertSame('claude-opus-4-7', $byRole['attacker']['model']);
        self::assertSame('claude-haiku-4-5', $byRole['reviewer']['model']);
        // attacker input = 100, reviewer input = ceil(100 * 0.25) = 25
        self::assertSame(100, $byRole['attacker']['input_tokens']);
        self::assertSame(25, $byRole['reviewer']['input_tokens']);
    }

    public function test_attacker_cost_in_breakdown_is_rounded_to_six_decimals(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 100),
            'maxIterations' => 1,
            'outputRatio' => 0.0,
            'reviewerInputRatio' => 0.0,
            'pricingProvider' => $this->nonZeroPricing(1.234567, 0.0),
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(0.000123, $auditReport->cost()->byRole()['attacker']['estimated_cost_usd']);
    }

    public function test_reviewer_cost_in_breakdown_is_rounded_to_six_decimals(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 100),
            'maxIterations' => 1,
            'outputRatio' => 0.0,
            'reviewerInputRatio' => 0.5,
            'pricingProvider' => $this->nonZeroPricing(1.234567, 0.0),
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(0.000062, $auditReport->cost()->byRole()['reviewer']['estimated_cost_usd']);
    }

    public function test_estimated_cost_sums_attacker_and_reviewer_contributions(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 100),
            'maxIterations' => 1,
            'outputRatio' => 0.0,
            'reviewerInputRatio' => 0.5,
            'pricingProvider' => $this->nonZeroPricing(1.234567, 0.0),
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(0.000185, $auditReport->cost()->estimatedCostUsd());
    }

    public function test_reviewer_input_token_estimate_uses_ceil_not_floor_or_round(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 100),
            'maxIterations' => 1,
            'outputRatio' => 0.5,
            'reviewerInputRatio' => 0.234,
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(24, $auditReport->cost()->byRole()['reviewer']['input_tokens']);
    }

    public function test_reviewer_output_token_estimate_uses_ceil_not_floor_or_round(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 100),
            'maxIterations' => 1,
            'outputRatio' => 0.146,
            'reviewerInputRatio' => 0.5,
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(8, $auditReport->cost()->byRole()['reviewer']['output_tokens']);
    }

    public function test_dry_run_falls_back_to_attacker_model_when_reviewer_model_blank(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 10),
            'primaryModel' => 'gpt-4o',
            'maxIterations' => 1,
            'outputRatio' => 0.5,
            'reviewerModel' => '',
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        $byRole = $auditReport->cost()->byRole();
        self::assertSame('gpt-4o', $byRole['attacker']['model']);
        self::assertSame('gpt-4o', $byRole['reviewer']['model']);
    }

    public function test_scanned_files_are_set_on_the_audit_context(): void
    {
        // Pins: `$auditContext->setProjectFiles($files)` — if removed, the resulting
        // AuditReport's `filesScanned` would be 0 instead of the actual count.
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [
                $this->makeProjectFile('a.php', 'a'),
                $this->makeProjectFile('b.php', 'b'),
                $this->makeProjectFile('c.php', 'c'),
            ],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 1),
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(3, $auditReport->filesScanned());
    }

    public function test_scan_paths_filter_files_before_estimation(): void
    {
        // Pins ScanPathFilter integration: without filter, all three files are
        // estimated; with `apps/api`, only the matching one contributes.
        $measuringTokenEstimator = $this->measuringEstimator();
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [
                $this->makeProjectFile('apps/api/src/A.php', 'aa'),     // 2 chars
                $this->makeProjectFile('apps/web/src/B.php', 'bbbbbb'), // 6 chars
                $this->makeProjectFile('libs/shared/C.php', 'cccc'),    // 4 chars
            ],
            'tokenEstimator' => $measuringTokenEstimator,
        ]);

        $estimateAuditCostUseCase->execute($this->tmpDir, ['apps/api']);

        self::assertSame(2, $measuringTokenEstimator->lastInputLength);
    }

    public function test_diff_since_ref_narrows_the_estimate_to_changed_files(): void
    {
        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['src/Changed.php']);

        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [
                $this->makeProjectFile('src/Changed.php', 'aa'),      // 2 chars
                $this->makeProjectFile('src/Unchanged.php', 'bbbbbb'), // 6 chars
            ],
            'tokenEstimator' => $this->lengthEchoingEstimator(),
            'maxIterations' => 1,
            'gitChangedFilesResolver' => $gitChangedFilesResolver,
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir, [], 'main');

        self::assertSame(2, $auditReport->cost()->byRole()['attacker']['input_tokens'], 'the estimate must reflect only the changed file, not the whole project');
        self::assertSame(1, $auditReport->filesScanned());
    }

    public function test_without_a_diff_since_ref_the_estimate_covers_every_file(): void
    {
        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['src/Changed.php']);

        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [
                $this->makeProjectFile('src/Changed.php', 'aa'),      // 2 chars
                $this->makeProjectFile('src/Unchanged.php', 'bbbbbb'), // 6 chars
            ],
            'tokenEstimator' => $this->lengthEchoingEstimator(),
            'maxIterations' => 1,
            'gitChangedFilesResolver' => $gitChangedFilesResolver,
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(8, $auditReport->cost()->byRole()['attacker']['input_tokens'], 'without --since, every file must still contribute to the estimate');
        self::assertSame(2, $auditReport->filesScanned());
    }

    public function test_primary_model_flows_through_to_audit_cost(): void
    {
        $estimateAuditCostUseCase = $this->makeUseCase([
            'files' => [$this->makeProjectFile('a.php', 'aaa')],
            'tokenEstimator' => $this->fixedEstimator(perRoundTokens: 1),
            'primaryModel' => 'claude-opus-4-7',
        ]);

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame('claude-opus-4-7', $auditReport->cost()->primaryModel());
    }

    public function test_max_iterations_defaults_to_three(): void
    {
        $estimateAuditCostUseCase = new EstimateAuditCostUseCase(
            $this->fixedScanner([$this->makeProjectFile('a.php', 'aaa')]),
            $this->fixedEstimator(perRoundTokens: 99),
            new CostCalculator($this->zeroPricing()),
            new NullLogger(),
            primaryModel: 'gpt-4o',
        );

        $auditReport = $estimateAuditCostUseCase->execute($this->tmpDir);

        self::assertSame(99 * 3, $auditReport->cost()->byRole()['attacker']['input_tokens']);
    }

    /**
     * @param array{
     *     files?: list<ProjectFile>,
     *     tokenEstimator?: TokenEstimatorInterface,
     *     logger?: LoggerInterface,
     *     primaryModel?: string,
     *     maxIterations?: int,
     *     outputRatio?: float,
     *     reviewerModel?: string,
     *     reviewerInputRatio?: float,
     *     pricingProvider?: PricingProviderInterface,
     *     gitChangedFilesResolver?: GitChangedFilesResolverInterface,
     * } $overrides
     */
    private function makeUseCase(array $overrides = []): EstimateAuditCostUseCase
    {
        $files = $overrides['files'] ?? [];
        $tokenEstimator = $overrides['tokenEstimator'] ?? $this->fixedEstimator(perRoundTokens: 0);
        $logger = $overrides['logger'] ?? new NullLogger();
        $primaryModel = $overrides['primaryModel'] ?? 'gpt-4o';
        $maxIterations = $overrides['maxIterations'] ?? 3;
        $outputRatio = $overrides['outputRatio'] ?? EstimateAuditCostUseCase::DEFAULT_OUTPUT_RATIO;
        $reviewerModel = $overrides['reviewerModel'] ?? '';
        $reviewerInputRatio = $overrides['reviewerInputRatio'] ?? EstimateAuditCostUseCase::DEFAULT_REVIEWER_INPUT_RATIO;
        $pricingProvider = $overrides['pricingProvider'] ?? $this->zeroPricing();
        $gitChangedFilesResolver = $overrides['gitChangedFilesResolver'] ?? null;

        return new EstimateAuditCostUseCase(
            $this->fixedScanner($files),
            $tokenEstimator,
            new CostCalculator($pricingProvider),
            $logger,
            $primaryModel,
            $maxIterations,
            $outputRatio,
            $reviewerModel,
            $reviewerInputRatio,
            $gitChangedFilesResolver,
        );
    }

    /**
     * @param list<ProjectFile> $files
     */
    private function fixedScanner(array $files): ProjectFileScannerInterface
    {
        return new class($files) implements ProjectFileScannerInterface {
            /** @param list<ProjectFile> $files */
            public function __construct(private readonly array $files) {}

            #[Override]
            public function scan(string $projectPath): array
            {
                return $this->files;
            }
        };
    }

    private function fixedEstimator(int $perRoundTokens): TokenEstimatorInterface
    {
        return new class($perRoundTokens) implements TokenEstimatorInterface {
            public function __construct(private readonly int $perRoundTokens) {}

            #[Override]
            public function estimateTokens(string $text, string $model): int
            {
                return $this->perRoundTokens;
            }
        };
    }

    /** Recording estimator — returns 0 but captures the length of the last input seen. */
    private function measuringEstimator(): MeasuringTokenEstimator
    {
        return new MeasuringTokenEstimator();
    }

    /** Returns the character length of whatever text it is given, so per-call results can be summed and asserted on. */
    private function lengthEchoingEstimator(): TokenEstimatorInterface
    {
        return new class implements TokenEstimatorInterface {
            #[Override]
            public function estimateTokens(string $text, string $model): int
            {
                return mb_strlen($text);
            }
        };
    }

    private function zeroPricing(): PricingProviderInterface
    {
        return new class implements PricingProviderInterface {
            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }
        };
    }

    /**
     * Non-zero pricing fixture that produces costs with at least six significant
     * decimals — used to pin the rounding mutators on the per-role cost rows
     * (`round(_, 6)`) which all collapse to 0.0 under `zeroPricing()`.
     */
    private function nonZeroPricing(float $inputPricePerMillion, float $outputPricePerMillion): PricingProviderInterface
    {
        return new class($inputPricePerMillion, $outputPricePerMillion) implements PricingProviderInterface {
            public function __construct(
                private readonly float $inputPricePerMillion,
                private readonly float $outputPricePerMillion,
            ) {}

            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return $this->inputPricePerMillion;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return $this->outputPricePerMillion;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }
        };
    }

    private function makeProjectFile(string $relative, string $content): ProjectFile
    {
        return ProjectFile::create($relative, $this->tmpDir.'/'.$relative, $content);
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/estimate_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        if (is_dir($this->tmpDir)) {
            rmdir($this->tmpDir);
        }
    }
}
