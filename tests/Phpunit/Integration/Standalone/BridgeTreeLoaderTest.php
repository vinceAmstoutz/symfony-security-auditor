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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Standalone;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\BridgeTree;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\BridgeTreeLoader;

final class BridgeTreeLoaderTest extends TestCase
{
    private const string BUNDLED_RELEASE = 'v0.14.1';

    private const string PLATFORM_CHECK_FAILURE = 'Composer detected issues in your platform: Your Composer dependencies require a PHP version ">= 9.0.0".';

    private const string LOADED_MARKER = 'loaded';

    private string $directory;

    private Filesystem $filesystem;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->directory = sys_get_temp_dir().'/ssa-bridge-loader-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->directory);
    }

    public function test_it_loads_a_tree_holding_the_bundled_release(): void
    {
        $this->writeAutoloader(\sprintf("touch(__DIR__.'/%s');", self::LOADED_MARKER));
        $this->recordAiPlatform(self::BUNDLED_RELEASE);

        $warning = $this->load();

        self::assertSame([null, true], [$warning, is_file($this->markerFile())]);
    }

    public function test_it_leaves_a_tree_holding_another_release_unloaded_for_the_commands_needing_it_to_report(): void
    {
        $this->writeAutoloader(\sprintf("touch(__DIR__.'/%s');", self::LOADED_MARKER));
        $this->recordAiPlatform('v0.12.0');

        $warning = $this->load();

        self::assertSame([null, false], [$warning, is_file($this->markerFile())]);
    }

    public function test_there_is_nothing_to_load_before_init_installed_a_tree(): void
    {
        self::assertNull($this->load());
    }

    #[DataProvider('platformChecksRefusingThisPhp')]
    public function test_a_tree_whose_platform_check_refuses_this_php_is_reported_instead_of_ending_the_process(string $platformCheck): void
    {
        $this->writeAutoloader($platformCheck);

        self::assertSame(
            \sprintf('The provider bridge under "%s" cannot be loaded by this binary: %s%sRun "init --provider=<platform> --force" to rebuild it for the bundled PHP.', $this->directory, self::PLATFORM_CHECK_FAILURE, \PHP_EOL),
            $this->load(),
        );
    }

    #[DataProvider('platformChecksRefusingThisPhp')]
    public function test_it_hands_errors_back_to_the_handler_it_found(string $platformCheck): void
    {
        $this->writeAutoloader($platformCheck);
        $handlerBefore = $this->currentErrorHandler();

        $this->load();

        self::assertSame($handlerBefore, $this->currentErrorHandler());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function platformChecksRefusingThisPhp(): iterable
    {
        yield 'thrown, as Composer 2.8.10 and later generate it' => [\sprintf('throw new RuntimeException(%s);', var_export(self::PLATFORM_CHECK_FAILURE, true))];
        yield 'raised as a fatal error, as earlier Composer versions generate it' => [\sprintf('trigger_error(%s, E_USER_ERROR);', var_export(self::PLATFORM_CHECK_FAILURE, true))];
    }

    public function test_it_hands_errors_back_to_the_handler_it_found_once_a_tree_is_loaded(): void
    {
        $this->writeAutoloader('');
        $handlerBefore = $this->currentErrorHandler();

        $this->load();

        self::assertSame($handlerBefore, $this->currentErrorHandler());
    }

    private function load(): ?string
    {
        return (new BridgeTreeLoader())->load(new BridgeTree($this->directory, self::BUNDLED_RELEASE));
    }

    private function writeAutoloader(string $body): void
    {
        $this->filesystem->dumpFile(\sprintf('%s/vendor/autoload.php', $this->directory), \sprintf("<?php\n\n%s\n", $body));
    }

    private function recordAiPlatform(string $version): void
    {
        $this->filesystem->dumpFile(
            \sprintf('%s/vendor/composer/installed.php', $this->directory),
            \sprintf("<?php return %s;\n", var_export(['versions' => ['symfony/ai-platform' => ['pretty_version' => $version]]], true)),
        );
    }

    private function markerFile(): string
    {
        return \sprintf('%s/vendor/%s', $this->directory, self::LOADED_MARKER);
    }

    private function currentErrorHandler(): mixed
    {
        $currentErrorHandler = set_error_handler(static fn (): bool => false);
        restore_error_handler();

        return $currentErrorHandler;
    }
}
