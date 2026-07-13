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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\ClassScore;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\EvalScorer;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\ExpectedFinding;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\GroundTruthManifest;

final class EvalScorerTest extends TestCase
{
    public function test_a_perfectly_reproduced_manifest_scores_full_precision_and_recall(): void
    {
        $groundTruthManifest = new GroundTruthManifest([
            new ExpectedFinding('src/A.php', 'sql_injection'),
            new ExpectedFinding('src/B.php', 'broken_access_control'),
        ]);

        $evalReport = (new EvalScorer())->score($groundTruthManifest, [
            ['file' => 'src/A.php', 'type' => 'sql_injection'],
            ['file' => 'src/B.php', 'type' => 'broken_access_control'],
        ]);

        self::assertSame(1.0, $evalReport->overall->precision());
        self::assertSame(1.0, $evalReport->overall->recall());
        self::assertSame(2, $evalReport->overall->truePositives);
    }

    public function test_a_missed_seed_is_a_false_negative(): void
    {
        $groundTruthManifest = new GroundTruthManifest([new ExpectedFinding('src/A.php', 'sql_injection')]);

        $evalReport = (new EvalScorer())->score($groundTruthManifest, []);

        self::assertSame(0, $evalReport->overall->truePositives);
        self::assertSame(1, $evalReport->overall->falseNegatives);
        self::assertSame(0.0, $evalReport->overall->recall());
    }

    public function test_a_finding_in_an_unseeded_decoy_file_is_a_false_positive(): void
    {
        $groundTruthManifest = new GroundTruthManifest([new ExpectedFinding('src/A.php', 'sql_injection')]);

        $evalReport = (new EvalScorer())->score($groundTruthManifest, [
            ['file' => 'src/A.php', 'type' => 'sql_injection'],
            ['file' => 'src/SafeDecoy.php', 'type' => 'sql_injection'],
        ]);

        self::assertSame(1, $evalReport->overall->truePositives);
        self::assertSame(1, $evalReport->overall->falsePositives);
        self::assertSame(0.5, $evalReport->overall->precision());
    }

    public function test_a_seed_reported_with_the_wrong_type_is_both_a_miss_and_a_false_positive(): void
    {
        $groundTruthManifest = new GroundTruthManifest([new ExpectedFinding('src/A.php', 'sql_injection')]);

        $evalReport = (new EvalScorer())->score($groundTruthManifest, [['file' => 'src/A.php', 'type' => 'xss']]);

        self::assertSame(0, $evalReport->overall->truePositives);
        self::assertSame(1, $evalReport->overall->falsePositives);
        self::assertSame(1, $evalReport->overall->falseNegatives);
        self::assertSame(0.0, $evalReport->overall->f1());
    }

    public function test_scores_are_broken_down_per_vulnerability_class_sorted_by_type(): void
    {
        $groundTruthManifest = new GroundTruthManifest([
            new ExpectedFinding('src/A.php', 'sql_injection'),
            new ExpectedFinding('src/B.php', 'broken_access_control'),
        ]);

        $evalReport = (new EvalScorer())->score($groundTruthManifest, [['file' => 'src/A.php', 'type' => 'sql_injection']]);

        self::assertSame(
            ['broken_access_control', 'sql_injection'],
            array_map(static fn (ClassScore $classScore): string => $classScore->type, $evalReport->perClass),
        );
        self::assertSame(0.0, $evalReport->perClass[0]->recall());
        self::assertSame(1.0, $evalReport->perClass[1]->recall());
    }

    public function test_repeated_findings_of_the_same_type_in_one_file_are_counted_once(): void
    {
        $groundTruthManifest = new GroundTruthManifest([new ExpectedFinding('src/A.php', 'sql_injection')]);

        $evalReport = (new EvalScorer())->score($groundTruthManifest, [
            ['file' => 'src/A.php', 'type' => 'sql_injection'],
            ['file' => 'src/A.php', 'type' => 'sql_injection'],
        ]);

        self::assertSame(1, $evalReport->overall->truePositives);
        self::assertSame(0, $evalReport->overall->falsePositives);
    }

    public function test_an_empty_manifest_with_no_findings_scores_perfect_by_convention(): void
    {
        $evalReport = (new EvalScorer())->score(new GroundTruthManifest([]), []);

        self::assertSame(1.0, $evalReport->overall->precision());
        self::assertSame(1.0, $evalReport->overall->recall());
        self::assertTrue($evalReport->meetsThresholds(1.0, 1.0));
    }

    public function test_meets_thresholds_is_false_when_recall_is_below_the_floor(): void
    {
        $groundTruthManifest = new GroundTruthManifest([
            new ExpectedFinding('src/A.php', 'sql_injection'),
            new ExpectedFinding('src/B.php', 'xss'),
        ]);

        $evalReport = (new EvalScorer())->score($groundTruthManifest, [['file' => 'src/A.php', 'type' => 'sql_injection']]);

        self::assertFalse($evalReport->meetsThresholds(0.9, 0.9));
        self::assertTrue($evalReport->meetsThresholds(1.0, 0.5));
    }

    public function test_to_array_exposes_overall_and_per_class_scores(): void
    {
        $groundTruthManifest = new GroundTruthManifest([new ExpectedFinding('src/A.php', 'sql_injection')]);

        $array = (new EvalScorer())->score($groundTruthManifest, [['file' => 'src/A.php', 'type' => 'sql_injection']])->toArray();

        self::assertSame('overall', $array['overall']['type']);
        self::assertSame(1, $array['overall']['true_positives']);
        self::assertCount(1, $array['per_class']);
        self::assertSame('sql_injection', $array['per_class'][0]['type']);
    }
}
