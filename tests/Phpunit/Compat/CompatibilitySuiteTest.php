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

use Composer\InstalledVersions;
use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Diff\AcceptedDifference;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Diff\AcceptedDifferences;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Diff\Difference;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Diff\ObservationDiffer;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner\ScenarioRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Runtime;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Scenario;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\ScenarioCatalog;

/**
 * Replays every scenario recorded from the last release on this tree and
 * compares what it observes with the recording. A difference fails unless
 * `accepted-differences.php` lists it; an entry there that no longer
 * matches any difference fails too, so the list never outlives what it
 * accepts. See CONTRIBUTING.md, "Compatibility Checks".
 */
final class CompatibilitySuiteTest extends TestCase
{
    private const string SCENARIO_NAME = '/^[a-z0-9][a-z0-9.\/-]*$/';

    private const string MINOR_VERSION = '/^v?(\d+\.\d+)/';

    /**
     * @return iterable<string, array{string}>
     */
    public static function scenarios(): iterable
    {
        return self::recorded(static fn (Scenario $scenario): bool => [] === $scenario->deprecations());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function scenariosCallingDeprecatedApi(): iterable
    {
        return self::recorded(static fn (Scenario $scenario): bool => [] !== $scenario->deprecations());
    }

    /**
     * @throws JsonException
     */
    #[DataProvider('scenarios')]
    #[RunInSeparateProcess]
    public function test_the_scenario_behaves_as_in_the_recorded_release(string $scenario): void
    {
        $this->assertBehavesAsRecorded($scenario);
    }

    /**
     * @throws JsonException
     */
    #[DataProvider('scenariosCallingDeprecatedApi')]
    #[RunInSeparateProcess]
    #[IgnoreDeprecations('vinceamstoutz/symfony-security-auditor')]
    public function test_the_deprecated_api_still_behaves_as_in_the_recorded_release(string $scenario): void
    {
        foreach (ScenarioCatalog::get($scenario)->deprecations() as $deprecation) {
            $this->expectUserDeprecationMessage($deprecation);
        }

        $this->assertBehavesAsRecorded($scenario);
    }

    /**
     * @throws JsonException
     */
    public function test_the_recordings_are_the_ones_the_recorder_wrote(): void
    {
        $environment = Recordings::environment();

        self::assertTrue(FixtureSeal::isIntact($environment), 'environment.json was edited by hand: record the suite again (see CONTRIBUTING.md).');
        self::assertSame($environment['recordings'] ?? null, Recordings::manifest(Recordings::directory()), 'A recording was edited by hand, added or removed outside tools/Compat/record.php: record it again (see CONTRIBUTING.md).');
    }

    /**
     * @throws JsonException
     */
    public function test_every_scenario_is_recorded_unless_the_recorder_could_not(): void
    {
        $unrecorded = Recordings::environment()['unrecorded'] ?? [];
        self::assertIsArray($unrecorded);
        $refusable = array_keys(array_filter(ScenarioCatalog::all(), static fn (Scenario $scenario): bool => $scenario->usesNullDevice()));
        $recordedOrRefused = [...Recordings::scenarios(), ...array_keys($unrecorded)];
        sort($recordedOrRefused);

        self::assertSame(array_keys(ScenarioCatalog::all()), $recordedOrRefused, 'Every scenario has a recording, and every recording a scenario: record the ones added (see CONTRIBUTING.md).');
        self::assertSame([], array_values(array_diff(array_keys($unrecorded), $refusable)), 'The recorder only leaves out a scenario that writes to the discard device.');
    }

    /**
     * @throws JsonException
     */
    public function test_this_run_replays_on_the_php_and_packages_the_recording_was_made_with(): void
    {
        $environment = Recordings::environment();
        $packages = $environment['packages'] ?? [];
        self::assertIsArray($packages);

        $recorded = ['php' => $this->minor($environment['php'] ?? null)];
        $installed = ['php' => $this->minor(\PHP_VERSION)];
        foreach (array_keys($packages) as $package) {
            $recorded[$package] = $this->minor($packages[$package]);
            $installed[$package] = $this->minor(InstalledVersions::isInstalled((string) $package) ? InstalledVersions::getPrettyVersion((string) $package) : null);
        }

        self::assertSame($recorded, $installed, 'The recordings replay on the PHP and package versions they were recorded with, to the minor version: run the suite as the Compatibility CI job does, with tests/Phpunit/Compat/composer.lock on PHP 8.3 (see CONTRIBUTING.md).');
    }

    public function test_every_scenario_name_is_lower_case(): void
    {
        self::assertSame([], array_values(array_filter(array_keys(ScenarioCatalog::all()), static fn (string $name): bool => 1 !== preg_match(self::SCENARIO_NAME, $name))), 'A scenario name is lower case, so two recordings never collide on a case-insensitive file system.');
    }

    public function test_every_accepted_difference_names_known_scenarios_and_an_unreleased_bullet(): void
    {
        $known = array_keys(ScenarioCatalog::all());
        $problems = [];
        foreach (AcceptedDifferences::all() as $acceptedDifference) {
            $problems = [...$problems, ...$this->problemsOf($acceptedDifference, $known)];
        }

        self::assertSame([], $problems);
    }

    /**
     * @param list<string> $known
     *
     * @return list<string>
     */
    private function problemsOf(AcceptedDifference $acceptedDifference, array $known): array
    {
        $problems = [];
        foreach ($acceptedDifference->scenarios as $pattern) {
            if ([] === array_filter($known, static fn (string $scenario): bool => fnmatch($pattern, $scenario, \FNM_NOESCAPE))) {
                $problems[] = \sprintf('%s names no known scenario with "%s"', $acceptedDifference->path, $pattern);
            }
        }

        foreach (array_filter($acceptedDifference->changelog, static fn (string $bullet): bool => !UnreleasedChangelog::announces($bullet)) as $bullet) {
            $problems[] = \sprintf('%s cites a pull request no bullet under ## [Unreleased] in CHANGELOG.md links: "%s"', $acceptedDifference->path, $bullet);
        }

        return $problems;
    }

    /**
     * @throws JsonException
     */
    private function assertBehavesAsRecorded(string $scenario): void
    {
        $recording = Recordings::load($scenario);
        $definition = ScenarioCatalog::get($scenario);
        $replayed = (new ScenarioRunner())->replay($definition, $recording['artifacts']);
        $differences = $this->differFor($definition)->diff($recording['result'], $replayed);
        $accepted = AcceptedDifferences::forScenario($scenario);

        $unaccepted = array_filter($differences, static fn (Difference $difference): bool => [] === array_filter($accepted, static fn (AcceptedDifference $acceptedDifference): bool => $acceptedDifference->covers($scenario, $difference)));
        $stale = array_filter($accepted, static fn (AcceptedDifference $acceptedDifference): bool => [] === array_filter($differences, static fn (Difference $difference): bool => $acceptedDifference->covers($scenario, $difference)));

        self::assertSame([], array_values(array_map(static fn (Difference $difference): string => $difference->describe(), $unaccepted)), \sprintf(
            'Scenario "%s" no longer behaves as in %s. Restore that behaviour, or, for a change the maintainer accepted, list it in tests/Phpunit/Compat/accepted-differences.php with a reason and its CHANGELOG bullet.',
            $scenario,
            Recordings::release(),
        ));
        self::assertSame([], array_values(array_map(static fn (AcceptedDifference $acceptedDifference): string => $acceptedDifference->describe(), $stale)), \sprintf(
            'These accepted differences no longer show in scenario "%s": take the scenario out of their entry in tests/Phpunit/Compat/accepted-differences.php.',
            $scenario,
        ));
    }

    /**
     * @param callable(Scenario): bool $filter
     *
     * @return iterable<string, array{string}>
     */
    private static function recorded(callable $filter): iterable
    {
        foreach (Recordings::scenarios() as $scenario) {
            if ($filter(ScenarioCatalog::get($scenario))) {
                yield $scenario => [$scenario];
            }
        }
    }

    private function differFor(Scenario $scenario): ObservationDiffer
    {
        return Runtime::Api === $scenario->runtime ? ObservationDiffer::exact() : ObservationDiffer::forReports();
    }

    private function minor(mixed $version): ?string
    {
        return \is_string($version) && 1 === preg_match(self::MINOR_VERSION, $version, $match) ? $match[1] : null;
    }
}
