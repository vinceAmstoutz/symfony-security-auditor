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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat;

use FilesystemIterator;
use JsonException;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use UnexpectedValueException;

/**
 * The recordings of the last release, under `Fixture/<X.Y.Z>/`: one JSON file
 * per scenario, as `tools/Compat/record.php` wrote them, and
 * `environment.json`, where the recorder notes the PHP and package versions
 * it recorded with, the manifest of the recordings (each scenario with the
 * SHA-256 of its recording), the scenarios it could not record, and the seal
 * over all of it.
 */
final readonly class Recordings
{
    public const string ENVIRONMENT = 'environment.json';

    private const string FIXTURE_DIR = __DIR__.'/Fixture';

    public static function release(): string
    {
        $releases = array_values(array_filter(
            false === ($entries = scandir(self::FIXTURE_DIR)) ? [] : $entries,
            static fn (string $entry): bool => 1 === preg_match('/^\d+\.\d+\.\d+$/', $entry),
        ));

        if (1 !== \count($releases)) {
            throw new UnexpectedValueException(\sprintf('The compatibility suite holds the recording of exactly one release, found: %s.', implode(', ', $releases)));
        }

        return $releases[0];
    }

    public static function directory(): string
    {
        return \sprintf('%s/%s', self::FIXTURE_DIR, self::release());
    }

    /**
     * @return list<string>
     */
    public static function scenarios(): array
    {
        return array_column(self::manifest(self::directory()), 'scenario');
    }

    /**
     * Each recording under the directory with its SHA-256, by scenario name:
     * the digest is the value of a `sha256` key, never of a key named after
     * the scenario, so no scanner reads it as a credential of that name.
     *
     * @return list<array{scenario: string, sha256: string}>
     */
    public static function manifest(string $directory): array
    {
        $manifest = [];
        /** @var SplFileInfo $fileInfo */
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS)) as $fileInfo) {
            $scenario = substr($fileInfo->getPathname(), \strlen($directory) + 1, -5);
            if (str_contains($scenario, '/')) {
                $manifest[] = ['scenario' => $scenario, 'sha256' => (string) hash_file('sha256', $fileInfo->getPathname())];
            }
        }

        usort($manifest, static fn (array $left, array $right): int => strcmp($left['scenario'], $right['scenario']));

        return $manifest;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws JsonException
     */
    public static function environment(): array
    {
        $environment = json_decode((string) file_get_contents(\sprintf('%s/%s', self::directory(), self::ENVIRONMENT)), true, 512, \JSON_THROW_ON_ERROR);

        return self::stringKeyed(self::ENVIRONMENT, \is_array($environment) ? $environment : []);
    }

    /**
     * @return array{artifacts: array<string, array{mode: string, base64: string}>, result: array<string, mixed>}
     *
     * @throws JsonException
     */
    public static function load(string $scenario): array
    {
        $file = \sprintf('%s/%s/%s.json', self::FIXTURE_DIR, self::release(), $scenario);
        if (!is_file($file)) {
            throw new UnexpectedValueException(\sprintf('Scenario "%s" has no recording: run "bin/castor compat:record" (see CONTRIBUTING.md).', $scenario));
        }

        $recording = json_decode((string) file_get_contents($file), true, 512, \JSON_THROW_ON_ERROR);
        if (!\is_array($recording) || !\is_array($recording['artifacts'] ?? null) || !\is_array($recording['result'] ?? null)) {
            throw new UnexpectedValueException(\sprintf('The recording of "%s" is not one the recorder writes.', $scenario));
        }

        return ['artifacts' => self::artifacts($scenario, $recording['artifacts']), 'result' => self::stringKeyed($scenario, $recording['result'])];
    }

    /**
     * @param array<mixed> $artifacts
     *
     * @return array<string, array{mode: string, base64: string}>
     */
    private static function artifacts(string $scenario, array $artifacts): array
    {
        $narrowed = [];
        foreach (self::stringKeyed($scenario, $artifacts) as $path => $artifact) {
            if (!\is_array($artifact) || !\is_string($artifact['mode'] ?? null) || !\is_string($artifact['base64'] ?? null)) {
                throw new UnexpectedValueException(\sprintf('The recording of "%s" holds an artifact the recorder does not write: %s.', $scenario, $path));
            }

            $narrowed[$path] = ['mode' => $artifact['mode'], 'base64' => $artifact['base64']];
        }

        return $narrowed;
    }

    /**
     * @param array<mixed> $values
     *
     * @return array<string, mixed>
     */
    private static function stringKeyed(string $scenario, array $values): array
    {
        $narrowed = [];
        foreach ($values as $key => $value) {
            if (!\is_string($key)) {
                throw new UnexpectedValueException(\sprintf('The recording of "%s" holds a list where the recorder writes a map.', $scenario));
            }

            $narrowed[$key] = $value;
        }

        return $narrowed;
    }
}
