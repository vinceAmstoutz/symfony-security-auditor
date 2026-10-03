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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bridge;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeTree;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\StaleBridgeTreeException;

final class BridgeTreeTest extends TestCase
{
    private const string BUNDLED_RELEASE = 'v0.14.1';

    private string $directory;

    private Filesystem $filesystem;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->directory = sys_get_temp_dir().'/ssa-bridge-tree-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->directory);
    }

    public function test_its_autoloader_is_the_one_composer_writes_under_the_directory(): void
    {
        self::assertSame(\sprintf('%s/vendor/autoload.php', $this->directory), (new BridgeTree($this->directory, self::BUNDLED_RELEASE))->autoloadFile());
    }

    public function test_it_is_installed_once_its_autoloader_exists(): void
    {
        $this->filesystem->dumpFile(\sprintf('%s/vendor/autoload.php', $this->directory), "<?php\n");

        self::assertTrue((new BridgeTree($this->directory, self::BUNDLED_RELEASE))->isInstalled());
    }

    public function test_it_is_not_installed_without_an_autoloader(): void
    {
        $this->recordInstalledPackages(['symfony/ai-platform' => ['pretty_version' => self::BUNDLED_RELEASE]]);

        self::assertFalse((new BridgeTree($this->directory, self::BUNDLED_RELEASE))->isInstalled());
    }

    public function test_a_tree_holding_another_ai_platform_release_is_refused_with_the_command_that_rebuilds_it(): void
    {
        $this->recordInstalledPackages(['symfony/ai-platform' => ['pretty_version' => 'v0.12.0']]);

        self::assertSame(
            \sprintf('The provider bridge under "%s" was installed for symfony/ai-platform v0.12.0, but this binary bundles v0.14.1: loaded, its classes would replace the bundled ones and fail every LLM call, so the binary leaves it unloaded. Rebuild it with "symfony-security-auditor init --provider=ollama --force" — init rewrites config.yaml, so give it your model and connection options again.', $this->directory),
            $this->refusalOf(new BridgeTree($this->directory, self::BUNDLED_RELEASE), 'ollama'),
        );
    }

    public function test_the_refusal_leaves_the_provider_to_fill_in_when_none_is_configured(): void
    {
        $this->recordInstalledPackages(['symfony/ai-platform' => ['pretty_version' => 'v0.13.0']]);

        self::assertStringContainsString(
            '"symfony-security-auditor init --provider=<platform> --force"',
            (string) $this->refusalOf(new BridgeTree($this->directory, self::BUNDLED_RELEASE), null),
        );
    }

    /**
     * @param array<string, mixed> $versions
     */
    #[DataProvider('loadableTrees')]
    public function test_a_tree_that_cannot_shadow_the_bundled_release_is_loadable(array $versions, ?string $bundledRelease): void
    {
        $this->recordInstalledPackages($versions);

        self::assertNull($this->refusalOf(new BridgeTree($this->directory, $bundledRelease), 'ollama'));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, ?string}>
     */
    public static function loadableTrees(): iterable
    {
        yield 'it holds the bundled release' => [['symfony/ai-platform' => ['pretty_version' => self::BUNDLED_RELEASE]], self::BUNDLED_RELEASE];
        yield 'the bundled release is unknown' => [['symfony/ai-platform' => ['pretty_version' => 'v0.12.0']], null];
        yield 'it holds no ai-platform at all' => [['symfony/ai-ollama-platform' => ['pretty_version' => 'v0.12.0']], self::BUNDLED_RELEASE];
        yield 'its ai-platform records no version' => [['symfony/ai-platform' => ['version' => '0.12.0.0']], self::BUNDLED_RELEASE];
    }

    public function test_a_tree_without_installed_package_data_is_loadable(): void
    {
        $this->filesystem->dumpFile(\sprintf('%s/vendor/autoload.php', $this->directory), "<?php\n");

        self::assertNull($this->refusalOf(new BridgeTree($this->directory, self::BUNDLED_RELEASE), 'ollama'));
    }

    public function test_installed_package_data_that_is_not_a_map_is_read_as_holding_nothing(): void
    {
        $this->filesystem->dumpFile(\sprintf('%s/vendor/composer/installed.php', $this->directory), "<?php return 'not an array';\n");

        self::assertNull($this->refusalOf(new BridgeTree($this->directory, self::BUNDLED_RELEASE), 'ollama'));
    }

    private function refusalOf(BridgeTree $bridgeTree, ?string $provider): ?string
    {
        try {
            $bridgeTree->assertLoadable($provider);
        } catch (StaleBridgeTreeException $staleBridgeTreeException) {
            return $staleBridgeTreeException->getMessage();
        }

        return null;
    }

    /**
     * @param array<string, mixed> $versions
     */
    private function recordInstalledPackages(array $versions): void
    {
        $this->filesystem->dumpFile(
            \sprintf('%s/vendor/composer/installed.php', $this->directory),
            \sprintf("<?php return %s;\n", var_export(['root' => ['name' => '__root__'], 'versions' => $versions], true)),
        );
    }
}
