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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Config;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFileReader;

final class StandaloneConfigFileReaderTest extends TestCase
{
    private const string ALIAS_BOMB = <<<'YAML'
        a0: &a0 [x, x, x, x, x, x, x, x, x, x]
        a1: &a1 [*a0, *a0, *a0, *a0, *a0, *a0, *a0, *a0, *a0, *a0]
        a2: &a2 [*a1, *a1, *a1, *a1, *a1, *a1, *a1, *a1, *a1, *a1]
        a3: &a3 [*a2, *a2, *a2, *a2, *a2, *a2, *a2, *a2, *a2, *a2]
        a4: &a4 [*a3, *a3, *a3, *a3, *a3, *a3, *a3, *a3, *a3, *a3]
        a5: &a5 [*a4, *a4, *a4, *a4, *a4, *a4, *a4, *a4, *a4, *a4]
        a6: &a6 [*a5, *a5, *a5, *a5, *a5, *a5, *a5, *a5, *a5, *a5]
        a7: &a7 [*a6, *a6, *a6, *a6, *a6, *a6, *a6, *a6, *a6, *a6]
        a8: &a8 [*a7, *a7, *a7, *a7, *a7, *a7, *a7, *a7, *a7, *a7]
        scan: {included_paths: *a8}

        YAML;

    private string $configFile;

    private Filesystem $filesystem;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configFile = sys_get_temp_dir().'/ssa-config-file-'.bin2hex(random_bytes(6)).'/.symfony-security-auditor.yaml';
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove(\dirname($this->configFile));
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_whose_aliases_expand_past_any_configuration_is_refused_before_it_is_walked(): void
    {
        $this->filesystem->dumpFile($this->configFile, self::ALIAS_BOMB);

        $this->expectException(MalformedProjectConfigException::class);
        $this->expectExceptionMessage(\sprintf('Config file "%s" holds 10000 values or more once its YAML aliases are expanded', $this->configFile));

        (new StandaloneConfigFileReader())->read($this->configFile);
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_holding_one_value_short_of_the_limit_is_read(): void
    {
        $this->writeExcludedPaths(9997);

        self::assertCount(9997, $this->excludedPathsRead());
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_reaching_the_limit_is_refused(): void
    {
        $this->writeExcludedPaths(9998);

        $this->expectException(MalformedProjectConfigException::class);

        (new StandaloneConfigFileReader())->read($this->configFile);
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_an_alias_that_merely_repeats_a_value_is_still_read(): void
    {
        $this->filesystem->dumpFile($this->configFile, "scan:\n    included_paths: &paths [src, config]\n    excluded_paths: *paths\n");

        self::assertSame(
            ['scan' => ['included_paths' => ['src', 'config'], 'excluded_paths' => ['src', 'config']]],
            (new StandaloneConfigFileReader())->read($this->configFile),
        );
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_missing_file_reads_as_empty(): void
    {
        self::assertSame([], (new StandaloneConfigFileReader())->read($this->configFile));
    }

    private function writeExcludedPaths(int $count): void
    {
        $this->filesystem->dumpFile(
            $this->configFile,
            \sprintf("scan:\n    excluded_paths:\n%s", implode('', array_map(static fn (int $index): string => \sprintf("        - path%d\n", $index), range(1, $count)))),
        );
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws MalformedProjectConfigException
     */
    private function excludedPathsRead(): array
    {
        $scan = (new StandaloneConfigFileReader())->read($this->configFile)['scan'] ?? null;
        $excludedPaths = \is_array($scan) ? ($scan['excluded_paths'] ?? null) : null;

        return \is_array($excludedPaths) ? $excludedPaths : [];
    }
}
