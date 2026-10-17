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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Diff;

use JsonException;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Recordings;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner\ScenarioRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Runtime;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\ScenarioCatalog;

/**
 * What `tools/Compat/draft-accepted.php` reports after `1.x` moved: for one
 * scenario, the differences no entry of `accepted-differences.php` accepts
 * and the entries that no longer show; across scenarios, a draft entry per
 * difference, with every scenario it shows in.
 */
final class DraftEntries
{
    private const int SUBJECT_WIDTH = 400;

    /** @var array<string, array{scenarios: list<string>, path: string, subject: string}> */
    private array $drafts = [];

    /** @var list<string> */
    private array $stale = [];

    /**
     * @return array{unaccepted: list<array{path: string, subject: string}>, stale: list<string>}
     *
     * @throws JsonException
     */
    public static function ofScenario(string $scenario): array
    {
        $recording = Recordings::load($scenario);
        $definition = ScenarioCatalog::get($scenario);
        $observationDiffer = Runtime::Api === $definition->runtime ? ObservationDiffer::exact() : ObservationDiffer::forReports();
        $differences = $observationDiffer->diff($recording['result'], (new ScenarioRunner())->replay($definition, $recording['artifacts']));
        $accepted = AcceptedDifferences::forScenario($scenario);

        $unaccepted = array_filter($differences, static fn (Difference $difference): bool => [] === array_filter($accepted, static fn (AcceptedDifference $acceptedDifference): bool => $acceptedDifference->covers($scenario, $difference)));
        $stale = array_filter($accepted, static fn (AcceptedDifference $acceptedDifference): bool => [] === array_filter($differences, static fn (Difference $difference): bool => $acceptedDifference->covers($scenario, $difference)));

        return [
            'unaccepted' => array_values(array_map(static fn (Difference $difference): array => ['path' => $difference->path, 'subject' => $difference->subject()], $unaccepted)),
            'stale' => array_values(array_map(static fn (AcceptedDifference $acceptedDifference): string => $acceptedDifference->describe(), $stale)),
        ];
    }

    /**
     * @param string $output what `ofScenario()` returned for the scenario, as JSON
     *
     * @return bool whether the output was one `ofScenario()` writes
     */
    public function add(string $scenario, string $output): bool
    {
        $result = json_decode($output, true);
        if (!\is_array($result) || !\is_array($result['unaccepted'] ?? null) || !\is_array($result['stale'] ?? null)) {
            return false;
        }

        foreach ($result['unaccepted'] as $difference) {
            $this->addDifference($scenario, \is_array($difference) ? $difference : []);
        }

        foreach (array_filter($result['stale'], \is_string(...)) as $entry) {
            $this->stale[] = \sprintf('%s: %s', $scenario, $entry);
        }

        return true;
    }

    /**
     * @return string the draft entries, as the PHP list `accepted-differences.php` returns
     */
    public function entries(): string
    {
        ksort($this->drafts);
        $entries = [];
        foreach ($this->drafts as $draft) {
            $entries[] = \sprintf(
                "    [\n        'scenarios' => %s,\n        'path' => %s,\n        'match' => %s,\n        'reason' => 'TODO',\n        'changelog' => '#TODO',\n    ],\n",
                var_export($draft['scenarios'], true),
                var_export($draft['path'], true),
                var_export($this->pattern($draft['subject']), true),
            );
        }

        return \sprintf("return [\n%s];\n", implode('', $entries));
    }

    /**
     * @return list<string>
     */
    public function stale(): array
    {
        return $this->stale;
    }

    /**
     * @param array<mixed> $difference
     */
    private function addDifference(string $scenario, array $difference): void
    {
        $path = $difference['path'] ?? null;
        $subject = $difference['subject'] ?? null;
        if (!\is_string($path) || !\is_string($subject)) {
            return;
        }

        $key = \sprintf("%s\0%s", $path, $subject);
        $this->drafts[$key] ??= ['scenarios' => [], 'path' => $path, 'subject' => $subject];
        $this->drafts[$key]['scenarios'][] = $scenario;
    }

    private function pattern(string $subject): string
    {
        $shown = mb_substr($subject, 0, self::SUBJECT_WIDTH);

        return \sprintf('/^%s%s/', preg_quote($shown, '/'), $shown === $subject ? '$' : '');
    }
}
