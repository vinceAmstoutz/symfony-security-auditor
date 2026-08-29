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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Tooling\Eval;

use JsonException;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\ClassScore;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\EvalBaseline;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\EvalReport;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\Exception\InvalidEvalBaselineException;

final class EvalBaselineTest extends TestCase
{
    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/ssa-eval-baseline-'.bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmpDir);
    }

    public function test_a_run_matching_its_own_recording_reports_no_drift(): void
    {
        $evalReport = $this->report(9, 1, 1);

        self::assertSame([], EvalBaseline::fromReport($evalReport)->driftAgainst($evalReport));
    }

    public function test_a_recall_regression_is_reported(): void
    {
        $evalBaseline = EvalBaseline::fromReport($this->report(10, 0, 0));

        $drift = $evalBaseline->driftAgainst($this->report(5, 0, 5));

        self::assertCount(2, $drift);
        self::assertStringContainsString('overall recall: baseline 1.0000, this run 0.5000.', $drift[0]);
        self::assertStringContainsString('sql_injection recall: baseline 1.0000, this run 0.5000.', $drift[1]);
    }

    public function test_an_improvement_is_reported_too_because_a_pure_move_should_change_nothing(): void
    {
        $evalBaseline = EvalBaseline::fromReport($this->report(5, 5, 0));

        $drift = $evalBaseline->driftAgainst($this->report(5, 0, 0));

        self::assertCount(2, $drift);
        self::assertStringContainsString('overall precision: baseline 0.5000, this run 1.0000.', $drift[0]);
    }

    public function test_a_class_the_baseline_never_saw_is_reported(): void
    {
        $evalReport = new EvalReport(new ClassScore('overall', 1, 0, 0), []);

        $drift = EvalBaseline::fromReport($evalReport)->driftAgainst($this->report(1, 0, 0));

        self::assertSame(['sql_injection: found by this run but absent from the baseline.'], $drift);
    }

    public function test_a_class_that_vanished_from_the_run_is_reported(): void
    {
        $evalBaseline = EvalBaseline::fromReport($this->report(1, 0, 0));

        $drift = $evalBaseline->driftAgainst(new EvalReport(new ClassScore('overall', 1, 0, 0), []));

        self::assertSame(['sql_injection: recorded in the baseline but absent from this run.'], $drift);
    }

    /**
     * @throws JsonException
     * @throws InvalidEvalBaselineException
     */
    public function test_a_recording_round_trips_through_the_file_format(): void
    {
        $evalReport = $this->report(7, 2, 1);
        $path = $this->tmpDir.'/eval-baseline.json';
        file_put_contents($path, EvalBaseline::fromReport($evalReport)->toJson());

        self::assertSame([], EvalBaseline::fromFile($path)->driftAgainst($evalReport));
    }

    /**
     * @throws JsonException
     */
    public function test_the_written_file_is_a_scores_object_keyed_by_class(): void
    {
        $json = EvalBaseline::fromReport($this->report(1, 0, 0))->toJson();

        self::assertSame(
            ['scores' => ['overall' => ['precision' => 1.0, 'recall' => 1.0], 'sql_injection' => ['precision' => 1.0, 'recall' => 1.0]]],
            json_decode($json, true, flags: \JSON_THROW_ON_ERROR),
        );
    }

    /**
     * @throws InvalidEvalBaselineException
     */
    public function test_a_missing_file_is_rejected(): void
    {
        $this->expectException(InvalidEvalBaselineException::class);
        $this->expectExceptionMessage('does not exist or is not readable');

        EvalBaseline::fromFile($this->tmpDir.'/absent.json');
    }

    /**
     * @throws InvalidEvalBaselineException
     */
    #[DataProvider('malformedBaselines')]
    public function test_a_malformed_file_is_rejected(string $contents, string $expectedMessage): void
    {
        $path = $this->tmpDir.'/eval-baseline.json';
        file_put_contents($path, $contents);

        $this->expectException(InvalidEvalBaselineException::class);
        $this->expectExceptionMessage($expectedMessage);

        EvalBaseline::fromFile($path);
    }

    /** @return iterable<string, array{string, string}> */
    public static function malformedBaselines(): iterable
    {
        yield 'not json' => ['not json{{{', 'is not valid JSON'];
        yield 'no scores object' => ['{"nope": 1}', 'must be a JSON object with a "scores" object'];
        yield 'scores is not an object' => ['{"scores": "nope"}', 'must be a JSON object with a "scores" object'];
        yield 'numeric class key' => ['{"scores": {"0": {"precision": 1, "recall": 1}}}', 'must be a JSON object with a "scores" object'];
        yield 'score is not an object' => ['{"scores": {"overall": 1}}', 'has an invalid score for "overall"'];
        yield 'missing recall' => ['{"scores": {"overall": {"precision": 1}}}', 'has an invalid score for "overall"'];
        yield 'non-numeric precision' => ['{"scores": {"overall": {"precision": "1", "recall": 1}}}', 'has an invalid score for "overall"'];
        yield 'precision above one' => ['{"scores": {"overall": {"precision": 1.5, "recall": 1}}}', 'has an invalid score for "overall"'];
        yield 'negative recall' => ['{"scores": {"overall": {"precision": 1, "recall": -0.1}}}', 'has an invalid score for "overall"'];
    }

    /**
     * @throws InvalidEvalBaselineException
     */
    public function test_an_integer_metric_is_accepted_as_a_float(): void
    {
        $path = $this->tmpDir.'/eval-baseline.json';
        file_put_contents($path, '{"scores": {"overall": {"precision": 1, "recall": 1}, "sql_injection": {"precision": 1, "recall": 1}}}');

        self::assertSame([], EvalBaseline::fromFile($path)->driftAgainst($this->report(1, 0, 0)));
    }

    private function report(int $truePositives, int $falsePositives, int $falseNegatives): EvalReport
    {
        return new EvalReport(
            new ClassScore(EvalBaseline::OVERALL, $truePositives, $falsePositives, $falseNegatives),
            [new ClassScore('sql_injection', $truePositives, $falsePositives, $falseNegatives)],
        );
    }
}
