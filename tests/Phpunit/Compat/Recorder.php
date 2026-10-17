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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\WritableFilePath;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner\ScenarioRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner\Workspace;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\Scenario;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario\ScenarioCatalog;

/**
 * What `tools/Compat/record.php` does for the checkout it autoloads: records
 * scenarios into `Fixture/<release>/`, refuses the ones it cannot record
 * there, and writes and seals `environment.json`.
 */
final readonly class Recorder
{
    public const int REFUSED = 3;

    private const array RECORDED_PACKAGES = ['symfony/console', 'symfony/config', 'symfony/dependency-injection', 'symfony/yaml', 'symfony/ai-platform', 'symfony/ai-bundle', 'mcp/sdk'];

    private const string DEVICE_WRITER = WritableFilePath::class;

    private const string DEVICE_WRITER_CHECK = 'isCharacterDevice';

    private const int JSON_FLAGS = \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_PRESERVE_ZERO_FRACTION | \JSON_THROW_ON_ERROR;

    public function __construct(
        private string $fixtureDir,
        private string $release,
    ) {}

    /**
     * Records each scenario, or notes why it cannot, and seals the result.
     *
     * @param list<string> $names
     *
     * @return bool whether every scenario was recorded
     *
     * @throws JsonException
     */
    public function record(array $names): bool
    {
        $filesystem = new Filesystem();
        $filesystem->mkdir($this->fixtureDir);

        $unrecorded = $this->unrecorded();
        $scenarioRunner = new ScenarioRunner();

        foreach ($names as $name) {
            $file = \sprintf('%s/%s.json', $this->fixtureDir, $name);
            $scenario = ScenarioCatalog::get($name);
            $reason = $this->refusal($scenario);
            unset($unrecorded[$name]);
            $filesystem->remove($file);

            if (null !== $reason) {
                $unrecorded[$name] = $reason;

                continue;
            }

            $filesystem->dumpFile($file, json_encode(['scenario' => $name, ...$scenarioRunner->record($scenario)], self::JSON_FLAGS)."\n");
        }

        $this->writeEnvironment($unrecorded);

        return [] === array_intersect($names, array_keys($unrecorded));
    }

    /**
     * Why this checkout cannot record the scenario here, if it cannot: a
     * release that saves a report through a temporary file and a rename
     * replaces the discard device it writes to, so a scenario writing to it is
     * recorded only by a process that cannot write `/dev`, or from a release
     * that writes a device in place.
     */
    public function refusal(Scenario $scenario): ?string
    {
        if (!$scenario->usesNullDevice() || !Workspace::canWriteSystemDevices() || $this->declares(self::DEVICE_WRITER, self::DEVICE_WRITER_CHECK)) {
            return null;
        }

        return 'it writes to the discard device, which this release replaces through a rename: record it as a user that cannot write /dev';
    }

    /**
     * @return array<string, string> why each scenario left out was, by name
     *
     * @throws JsonException
     */
    public function unrecorded(): array
    {
        $file = \sprintf('%s/%s', $this->fixtureDir, Recordings::ENVIRONMENT);
        $environment = is_file($file) ? json_decode((string) file_get_contents($file), true, 512, \JSON_THROW_ON_ERROR) : [];
        $unrecorded = \is_array($environment) && \is_array($environment['unrecorded'] ?? null) ? $environment['unrecorded'] : [];

        $reasons = [];
        foreach ($unrecorded as $name => $reason) {
            if (\is_string($name) && \is_string($reason)) {
                $reasons[$name] = $reason;
            }
        }

        return $reasons;
    }

    /**
     * @param array<string, string> $unrecorded
     *
     * @throws JsonException
     */
    private function writeEnvironment(array $unrecorded): void
    {
        $packages = [];
        foreach (self::RECORDED_PACKAGES as $package) {
            $packages[$package] = InstalledVersions::isInstalled($package) ? InstalledVersions::getPrettyVersion($package) : null;
        }

        ksort($unrecorded);
        $environment = FixtureSeal::sealed([
            'release' => $this->release,
            'php' => \PHP_VERSION,
            'packages' => $packages,
            'recordings' => Recordings::manifest($this->fixtureDir),
            'unrecorded' => $unrecorded,
        ]);

        (new Filesystem())->dumpFile(\sprintf('%s/%s', $this->fixtureDir, Recordings::ENVIRONMENT), json_encode($environment, self::JSON_FLAGS)."\n");
    }

    private function declares(string $class, string $method): bool
    {
        return class_exists($class) && method_exists($class, $method);
    }
}
