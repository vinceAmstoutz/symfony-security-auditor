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

use JsonException;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\Exception\InvalidEvalBaselineException;

/**
 * A recorded `bin/castor eval` result, so detection quality is a gate instead
 * of a number someone eyeballs. Coverage and MSI prove the code still runs;
 * only this proves the auditor still finds the same vulnerabilities, which is
 * the property a wide no-behaviour-change refactor has to preserve.
 *
 * Any difference beyond {@see self::TOLERANCE} is reported — an improvement
 * included. On a pure move a changed score means something moved that was not
 * supposed to, and re-recording is a deliberate act.
 */
final readonly class EvalBaseline
{
    public const string OVERALL = 'overall';

    private const float TOLERANCE = 1.0e-9;

    /**
     * @param array<string, array{precision: float, recall: float}> $scoresByType
     */
    private function __construct(private array $scoresByType) {}

    /**
     * @throws InvalidEvalBaselineException
     */
    public static function fromFile(string $path): self
    {
        $contents = is_file($path) ? file_get_contents($path) : false;
        if (false === $contents) {
            throw InvalidEvalBaselineException::forUnreadablePath($path);
        }

        try {
            $decoded = json_decode($contents, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw InvalidEvalBaselineException::fromJsonException($path, $jsonException);
        }

        $scores = \is_array($decoded) ? ($decoded['scores'] ?? null) : null;
        if (!\is_array($scores)) {
            throw InvalidEvalBaselineException::forMissingScoresObject($path);
        }

        return new self(self::parseScores($scores, $path));
    }

    public static function fromReport(EvalReport $evalReport): self
    {
        $scores = [self::OVERALL => self::scoreOf($evalReport->overall)];
        foreach ($evalReport->perClass as $classScore) {
            $scores[$classScore->type] = self::scoreOf($classScore);
        }

        return new self($scores);
    }

    /**
     * @throws JsonException
     */
    public function toJson(): string
    {
        return json_encode(['scores' => $this->scoresByType], \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR | \JSON_PRESERVE_ZERO_FRACTION)."\n";
    }

    /**
     * @return list<string> one human-readable line per drift, empty when the
     *                      report matches the baseline exactly
     */
    public function driftAgainst(EvalReport $evalReport): array
    {
        $actual = self::fromReport($evalReport)->scoresByType;

        $drift = [];
        foreach ($this->scoresByType as $type => $recorded) {
            $measured = $actual[$type] ?? null;
            if (null === $measured) {
                $drift[] = \sprintf('%s: recorded in the baseline but absent from this run.', $type);
                continue;
            }

            $drift = [...$drift, ...self::metricDrift($type, $recorded, $measured)];
        }

        foreach (array_keys($actual) as $type) {
            if (null === ($this->scoresByType[$type] ?? null)) {
                $drift[] = \sprintf('%s: found by this run but absent from the baseline.', $type);
            }
        }

        return $drift;
    }

    /**
     * @param array{precision: float, recall: float} $recorded
     * @param array{precision: float, recall: float} $actual
     *
     * @return list<string>
     */
    private static function metricDrift(string $type, array $recorded, array $actual): array
    {
        $drift = [];
        foreach (['precision', 'recall'] as $metric) {
            if (abs($recorded[$metric] - $actual[$metric]) > self::TOLERANCE) {
                $drift[] = \sprintf('%s %s: baseline %.4f, this run %.4f.', $type, $metric, $recorded[$metric], $actual[$metric]);
            }
        }

        return $drift;
    }

    /**
     * @return array{precision: float, recall: float}
     */
    private static function scoreOf(ClassScore $classScore): array
    {
        return ['precision' => $classScore->precision(), 'recall' => $classScore->recall()];
    }

    /**
     * @param array<array-key, mixed> $scores
     *
     * @return array<string, array{precision: float, recall: float}>
     *
     * @throws InvalidEvalBaselineException
     */
    private static function parseScores(array $scores, string $path): array
    {
        $parsed = [];
        foreach ($scores as $type => $score) {
            if (!\is_string($type)) {
                throw InvalidEvalBaselineException::forMissingScoresObject($path);
            }

            $parsed[$type] = self::parseScore($score, $path, $type);
        }

        return $parsed;
    }

    /**
     * @return array{precision: float, recall: float}
     *
     * @throws InvalidEvalBaselineException
     */
    private static function parseScore(mixed $score, string $path, string $type): array
    {
        if (!\is_array($score)) {
            throw InvalidEvalBaselineException::forInvalidScore($path, $type);
        }

        return [
            'precision' => self::parseMetric($score['precision'] ?? null, $path, $type),
            'recall' => self::parseMetric($score['recall'] ?? null, $path, $type),
        ];
    }

    /**
     * @throws InvalidEvalBaselineException
     */
    private static function parseMetric(mixed $metric, string $path, string $type): float
    {
        if (!\is_int($metric) && !\is_float($metric)) {
            throw InvalidEvalBaselineException::forInvalidScore($path, $type);
        }

        $value = (float) $metric;
        if ($value < 0.0 || $value > 1.0) {
            throw InvalidEvalBaselineException::forInvalidScore($path, $type);
        }

        return $value;
    }
}
