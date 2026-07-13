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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval;

/**
 * Scores an audit run against its ground-truth manifest at (file, type)
 * granularity: a seeded finding the run reproduced is a true positive, one it
 * missed a false negative, and a reported finding with no matching seed a
 * false positive — so safe "decoy" files raise the false-positive count when
 * the auditor flags them. Precision and recall are reported overall and per
 * vulnerability class.
 */
final readonly class EvalScorer
{
    /**
     * @param list<array{file: string, type: string}> $actualFindings
     */
    public function score(GroundTruthManifest $groundTruthManifest, array $actualFindings): EvalReport
    {
        $expectedKeys = $this->keyedByType(array_map(
            static fn (ExpectedFinding $expectedFinding): array => ['file' => $expectedFinding->file, 'type' => $expectedFinding->type],
            $groundTruthManifest->findings,
        ));
        $actualKeys = $this->keyedByType($actualFindings);

        $types = array_values(array_unique([...array_keys($expectedKeys), ...array_keys($actualKeys)]));
        sort($types);

        $perClass = array_map(
            fn (string $type): ClassScore => $this->classScore($type, $expectedKeys[$type] ?? [], $actualKeys[$type] ?? []),
            $types,
        );

        return new EvalReport($this->aggregate($perClass), $perClass);
    }

    /**
     * @param array<string, true> $expected file-keys seeded for this type
     * @param array<string, true> $actual   file-keys reported for this type
     */
    private function classScore(string $type, array $expected, array $actual): ClassScore
    {
        $truePositives = \count(array_intersect_key($expected, $actual));

        return new ClassScore(
            $type,
            $truePositives,
            \count($actual) - $truePositives,
            \count($expected) - $truePositives,
        );
    }

    /**
     * @param list<ClassScore> $perClass
     */
    private function aggregate(array $perClass): ClassScore
    {
        $truePositives = 0;
        $falsePositives = 0;
        $falseNegatives = 0;
        foreach ($perClass as $classScore) {
            $truePositives += $classScore->truePositives;
            $falsePositives += $classScore->falsePositives;
            $falseNegatives += $classScore->falseNegatives;
        }

        return new ClassScore('overall', $truePositives, $falsePositives, $falseNegatives);
    }

    /**
     * Deduplicates to a set of file-keys per type, so a class is scored as
     * present-or-absent per file rather than double-counting repeated findings.
     *
     * @param list<array{file: string, type: string}> $findings
     *
     * @return array<string, array<string, true>>
     */
    private function keyedByType(array $findings): array
    {
        $byType = [];
        foreach ($findings as $finding) {
            $byType[$finding['type']][$finding['file']] = true;
        }

        return $byType;
    }
}
