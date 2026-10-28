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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Configuration;

use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\FixtureSeal;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\UnreleasedChangelog;

/**
 * The bundle configuration of this tree is a compatible superset of the one
 * recorded from the last release (`Fixture/<X.Y.Z>.json`, written by
 * `tools/Compat/record-configuration.php`): no path is gone, no default
 * changed, no choice or bound narrowed, no value the release took is refused
 * or read differently, a key a project configuration could set still can,
 * one only the user could set still cannot, and every published container
 * parameter keeps its value, for the default configuration and for each
 * profile, unless `accepted-differences.php` accepts the change. A new path
 * must be documented.
 */
final class ConfigurationCompatibilityTest extends TestCase
{
    private const string FIXTURE_DIR = __DIR__.'/Fixture';

    private const string ROOT = 'symfony_security_auditor';

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     *
     * @throws JsonException
     */
    public static function recordedPaths(): iterable
    {
        foreach (self::recording()['paths'] as $path => $recorded) {
            yield $path => [$path, $recorded];
        }
    }

    /**
     * @param array<string, mixed> $recorded
     */
    #[DataProvider('recordedPaths')]
    public function test_a_recorded_path_keeps_its_contract(string $path, array $recorded): void
    {
        $nodes = ConfigurationTree::nodes();
        self::assertArrayHasKey($path, $nodes, \sprintf('"%s" was removed.', $path));

        $current = ConfigurationSnapshot::ofPath($nodes, $path);

        self::assertSame([], $this->unacceptedNarrowings($path, ContractComparison::narrowings($recorded, $current)), \sprintf('"%s" no longer takes what the recorded release took: restore it, or accept the change in tests/Phpunit/Compat/Configuration/accepted-differences.php with the CHANGELOG.md bullet that announces it.', $path));
    }

    /**
     * @throws JsonException
     */
    public function test_every_accepted_contract_change_is_announced_and_still_shows(): void
    {
        $problems = [];
        foreach ($this->acceptedContractChanges() as $acceptedContractChange) {
            $problems = [...$problems, ...$this->contractChangeProblems($acceptedContractChange)];
        }

        self::assertSame([], $problems);
    }

    /**
     * @throws JsonException
     */
    public function test_the_snapshot_is_the_one_the_recorder_wrote(): void
    {
        self::assertTrue(FixtureSeal::isIntact(self::fixture()), 'The configuration snapshot was edited by hand: record it again from the release with tools/Compat/record-configuration.php (see CONTRIBUTING.md).');
    }

    /**
     * @throws JsonException
     */
    public function test_every_published_container_parameter_keeps_its_value_unless_a_change_is_accepted(): void
    {
        $accepted = $this->acceptedChanges();
        $unaccepted = array_filter(
            $this->changedParameters(),
            static fn (string $parameter): bool => [] === array_filter($accepted, static fn (AcceptedParameterChange $acceptedParameterChange): bool => $acceptedParameterChange->covers($parameter)),
        );

        self::assertSame([], array_keys($unaccepted), 'A published container parameter changed value: restore it, or accept the change in tests/Phpunit/Compat/Configuration/accepted-differences.php with the CHANGELOG.md bullet that announces it.');
    }

    /**
     * @throws JsonException
     */
    public function test_every_accepted_parameter_change_is_announced_and_still_shows(): void
    {
        $changed = $this->changedParameters();
        $problems = [];

        foreach ($this->acceptedChanges() as $acceptedParameterChange) {
            if (!UnreleasedChangelog::announces($acceptedParameterChange->changelog)) {
                $problems[] = \sprintf('"%s" cites a pull request no bullet under ## [Unreleased] in CHANGELOG.md links: %s', implode('", "', $acceptedParameterChange->parameters), $acceptedParameterChange->changelog);
            }

            if ([] === array_filter($changed, $acceptedParameterChange->covers(...))) {
                $problems[] = \sprintf('"%s" no longer differs from the recorded release: remove the entry.', implode('", "', $acceptedParameterChange->parameters));
            }
        }

        self::assertSame([], $problems);
    }

    /**
     * @throws JsonException
     */
    public function test_every_path_added_since_the_recorded_release_is_documented(): void
    {
        $recorded = self::recording()['paths'];
        $versioning = (string) file_get_contents(__DIR__.'/../../../../docs/versioning.md');
        $schema = json_decode((string) file_get_contents(__DIR__.'/../../../../resources/schema.json'), true, 512, \JSON_THROW_ON_ERROR);
        $undocumented = [];

        foreach (array_keys(ConfigurationTree::nodes()) as $path) {
            if (\array_key_exists($path, $recorded)) {
                continue;
            }

            if (!DocumentedPaths::isListed($path, $recorded, $versioning) || !DocumentedPaths::isInSchema($path, $schema, self::ROOT)) {
                $undocumented[] = $path;
            }
        }

        self::assertSame([], $undocumented, 'A key added since the recorded release is listed in docs/versioning.md and described in resources/schema.json.');
    }

    /**
     * @return array<string, string> each parameter that changed, by configuration then name, as `configuration: name`
     *
     * @throws JsonException
     */
    private function changedParameters(): array
    {
        $changed = [];
        foreach (self::recording()['parameters'] as $configuration => $recordedParameters) {
            $current = $this->currentParameters($configuration);
            foreach (self::stringKeyed($recordedParameters) as $name => $value) {
                if (!\array_key_exists($name, $current) || $current[$name] !== $value) {
                    $changed[\sprintf('%s: %s', $configuration, $name)] = $name;
                }
            }
        }

        return $changed;
    }

    /**
     * @return array<string, mixed>
     */
    private function currentParameters(string $configuration): array
    {
        return ConfigurationSnapshot::DEFAULT_CONFIGURATION === $configuration
            ? ConfigurationProbe::parameters()
            : ConfigurationProbe::parameters(substr($configuration, \strlen(ConfigurationSnapshot::PROFILE_CONFIGURATION)));
    }

    /**
     * @return list<string>
     *
     * @throws JsonException
     */
    private function contractChangeProblems(AcceptedContractChange $acceptedContractChange): array
    {
        $problems = UnreleasedChangelog::announces($acceptedContractChange->changelog) ? [] : [\sprintf('"%s" cites a pull request no bullet under ## [Unreleased] in CHANGELOG.md links: %s', implode('", "', $acceptedContractChange->paths), $acceptedContractChange->changelog)];
        foreach ($acceptedContractChange->paths as $path) {
            if ([] === array_intersect($acceptedContractChange->narrowings, $this->currentNarrowings($path))) {
                $problems[] = \sprintf('"%s" no longer differs from the recorded release as accepted: remove the entry.', $path);
            }
        }

        return $problems;
    }

    /**
     * @return list<string>
     *
     * @throws JsonException
     */
    private function currentNarrowings(string $path): array
    {
        $nodes = ConfigurationTree::nodes();
        $recorded = self::recording()['paths'];

        return \array_key_exists($path, $recorded) && \array_key_exists($path, $nodes) ? ContractComparison::narrowings($recorded[$path], ConfigurationSnapshot::ofPath($nodes, $path)) : [];
    }

    /**
     * @param list<string> $narrowings
     *
     * @return list<string>
     */
    private function unacceptedNarrowings(string $path, array $narrowings): array
    {
        $accepted = $this->acceptedContractChanges();

        return array_values(array_filter($narrowings, static fn (string $narrowing): bool => [] === array_filter($accepted, static fn (AcceptedContractChange $acceptedContractChange): bool => $acceptedContractChange->covers($path, $narrowing))));
    }

    /**
     * @return list<AcceptedParameterChange>
     */
    private function acceptedChanges(): array
    {
        return array_values(array_map(static fn (array $entry): AcceptedParameterChange => AcceptedParameterChange::fromArray($entry), array_filter($this->acceptedEntries(), static fn (array $entry): bool => !\array_key_exists('paths', $entry))));
    }

    /**
     * @return list<AcceptedContractChange>
     */
    private function acceptedContractChanges(): array
    {
        return array_values(array_map(static fn (array $entry): AcceptedContractChange => AcceptedContractChange::fromArray($entry), array_filter($this->acceptedEntries(), static fn (array $entry): bool => \array_key_exists('paths', $entry))));
    }

    /**
     * @return list<array<mixed>>
     */
    private function acceptedEntries(): array
    {
        $entries = require __DIR__.'/accepted-differences.php';
        self::assertIsArray($entries);

        return array_values(array_map(static fn (mixed $entry): array => \is_array($entry) ? $entry : [], $entries));
    }

    /**
     * @return array{paths: array<string, array<string, mixed>>, parameters: array<string, mixed>}
     *
     * @throws JsonException
     */
    private static function recording(): array
    {
        $recording = self::fixture();

        $paths = [];
        foreach (self::stringKeyed($recording['paths'] ?? null) as $path => $recorded) {
            $paths[$path] = self::stringKeyed($recorded);
        }

        return ['paths' => $paths, 'parameters' => self::stringKeyed($recording['parameters'] ?? null)];
    }

    /**
     * @return array<string, mixed>
     *
     * @throws JsonException
     */
    private static function fixture(): array
    {
        $files = glob(\sprintf('%s/*.*.*.json', self::FIXTURE_DIR));
        self::assertIsArray($files);
        self::assertCount(1, $files, 'The fixture directory holds the configuration of exactly one release.');

        return self::stringKeyed(json_decode((string) file_get_contents($files[0]), true, 512, \JSON_THROW_ON_ERROR));
    }

    /**
     * @return array<string, mixed>
     */
    private static function stringKeyed(mixed $value): array
    {
        self::assertIsArray($value);

        return array_filter($value, \is_string(...), \ARRAY_FILTER_USE_KEY);
    }
}
