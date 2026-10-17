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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform;

/**
 * Turns the `FINDING {json}` markers of the files an attacker prompt carries
 * into the findings the scripted model reports. A marker may name the
 * iteration it is reported in (`iter`) and the only model that reports it
 * (`only_model`); every key it leaves out takes a default.
 */
final readonly class FindingMarkers
{
    private const array DEFAULTS = [
        'type' => 'broken_access_control',
        'severity' => 'high',
        'description' => 'desc',
        'line_start' => 1,
        'vulnerable_code' => 'code',
        'attack_vector' => 'vector',
        'proof' => 'proof',
        'remediation' => 'fix',
        'confidence' => 0.9,
    ];

    /**
     * @return list<array<string, mixed>>
     */
    public static function findingsIn(string $prompt, string $model): array
    {
        $findings = [];
        foreach (PromptReader::fileBlocks($prompt) as $filePath => $content) {
            foreach (self::markersIn($content) as $marker) {
                $finding = self::reported($marker, $filePath, $prompt, $model);
                if (null !== $finding) {
                    $findings[] = $finding;
                }
            }
        }

        return $findings;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private static function markersIn(string $content): array
    {
        preg_match_all('/FINDING (\{.*\})/', $content, $matches);

        $markers = [];
        foreach ($matches[1] as $json) {
            $marker = json_decode($json, true);
            if (\is_array($marker)) {
                $markers[] = array_filter($marker, is_string(...), \ARRAY_FILTER_USE_KEY);
            }
        }

        return $markers;
    }

    /**
     * @param array<string, mixed> $marker
     *
     * @return array<string, mixed>|null
     */
    private static function reported(array $marker, string $filePath, string $prompt, string $model): ?array
    {
        $iteration = $marker['iter'] ?? null;
        $onlyModel = $marker['only_model'] ?? null;
        unset($marker['iter'], $marker['only_model']);

        if (null !== $iteration && PlatformSession::promptOrdinal($filePath, $prompt) !== $iteration) {
            return null;
        }

        if (null !== $onlyModel && $onlyModel !== $model) {
            return null;
        }

        return $marker + ['line_end' => $marker['line_start'] ?? 1] + ['title' => \sprintf('Finding in %s', $filePath), 'file_path' => $filePath] + self::DEFAULTS;
    }
}
