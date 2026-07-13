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
 * The outcome of scoring one audit run against its ground-truth manifest: an
 * aggregate {@see ClassScore} plus one per vulnerability class.
 */
final readonly class EvalReport
{
    /**
     * @param list<ClassScore> $perClass
     */
    public function __construct(
        public ClassScore $overall,
        public array $perClass,
    ) {}

    public function meetsThresholds(float $minPrecision, float $minRecall): bool
    {
        return $this->overall->precision() >= $minPrecision && $this->overall->recall() >= $minRecall;
    }

    /**
     * @return array{
     *     overall: array{type: string, precision: float, recall: float, f1: float, true_positives: int, false_positives: int, false_negatives: int},
     *     per_class: list<array{type: string, precision: float, recall: float, f1: float, true_positives: int, false_positives: int, false_negatives: int}>
     * }
     */
    public function toArray(): array
    {
        return [
            'overall' => $this->classToArray($this->overall),
            'per_class' => array_map($this->classToArray(...), $this->perClass),
        ];
    }

    /**
     * @return array{type: string, precision: float, recall: float, f1: float, true_positives: int, false_positives: int, false_negatives: int}
     */
    private function classToArray(ClassScore $classScore): array
    {
        return [
            'type' => $classScore->type,
            'precision' => $classScore->precision(),
            'recall' => $classScore->recall(),
            'f1' => $classScore->f1(),
            'true_positives' => $classScore->truePositives,
            'false_positives' => $classScore->falsePositives,
            'false_negatives' => $classScore->falseNegatives,
        ];
    }
}
