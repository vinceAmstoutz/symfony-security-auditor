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

use Closure;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\BridgeInstallationFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;

final class ComposerBridgeInstallerTest extends TestCase
{
    private const string AI_BUNDLE_CLASS = __DIR__.'/../../../../vendor/symfony/ai-bundle/src/AiBundle.php';

    private const string UNTOUCHED_SYMLINK_TARGET = '{"name":"not the manifest"}
';

    private const string PINNED_MANIFEST = '{
    "config": {
        "platform": {
            "php": "8.3.99"
        }
    }
}
';

    private const string PINNED_MANIFEST_WITH_PLATFORM_RELEASE = '{
    "config": {
        "platform": {
            "php": "8.3.99"
        }
    },
    "require": {
        "symfony/ai-platform": "v0.14.1"
    }
}
';

    private string $targetDirectory;

    private string $outsideTarget;

    private Filesystem $filesystem;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->targetDirectory = sys_get_temp_dir().'/ssa-bridge-'.bin2hex(random_bytes(6));
        $this->outsideTarget = sys_get_temp_dir().'/ssa-bridge-symlink-target-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove([$this->targetDirectory, $this->outsideTarget]);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_initialises_the_target_directory_as_a_composer_project_pinned_to_the_runtime_php(): void
    {
        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess(), platformPhpVersion: '8.3.99'))->install('anthropic', $this->targetDirectory);

        self::assertStringEqualsFile($this->targetDirectory.'/composer.json', self::PINNED_MANIFEST);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_wraps_a_manifest_write_io_failure_as_a_bridge_installation_failed_exception(): void
    {
        $blockingFile = $this->targetDirectory.'/not-a-directory';
        $this->filesystem->dumpFile($blockingFile, 'x');

        $this->expectException(BridgeInstallationFailedException::class);

        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess()))->install('anthropic', $blockingFile);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_refuses_to_write_through_a_symlinked_manifest_path(): void
    {
        $this->filesystem->mkdir($this->targetDirectory);
        $this->filesystem->dumpFile($this->outsideTarget, self::UNTOUCHED_SYMLINK_TARGET);
        symlink($this->outsideTarget, $this->targetDirectory.'/composer.json');

        try {
            $this->expectException(BridgeInstallationFailedException::class);

            (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess()))->install('anthropic', $this->targetDirectory);
        } finally {
            self::assertStringEqualsFile($this->outsideTarget, self::UNTOUCHED_SYMLINK_TARGET);
        }
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_pins_the_bridge_tree_to_the_bundled_ai_platform_release(): void
    {
        $captured = [];
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static function (string $package, ?string $aiPlatformPin, string $targetDirectory) use (&$captured): Process {
            $captured[] = [$package, $aiPlatformPin];

            return new Process(['true']);
        }, platformPhpVersion: '8.3.99', aiPlatformPin: 'v0.14.1');

        $composerBridgeInstaller->install('anthropic', $this->targetDirectory);

        self::assertStringEqualsFile($this->targetDirectory.'/composer.json', self::PINNED_MANIFEST_WITH_PLATFORM_RELEASE);
        self::assertSame([['symfony/ai-anthropic-platform', 'v0.14.1']], $captured);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_keeps_the_other_keys_of_an_existing_manifest_while_refreshing_its_pins(): void
    {
        $this->filesystem->dumpFile($this->targetDirectory.'/composer.json', '{"name":"acme/app","config":{"platform":{"php":"8.1.0"},"sort-packages":true},"require":{"symfony/ai-platform":"v0.13.0","acme/extra":"^1.0"}}');

        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess(), platformPhpVersion: '8.3.99', aiPlatformPin: 'v0.14.1'))->install('anthropic', $this->targetDirectory);

        self::assertSame(
            [
                'name' => 'acme/app',
                'config' => ['platform' => ['php' => '8.3.99'], 'sort-packages' => true],
                'require' => ['symfony/ai-platform' => 'v0.14.1', 'acme/extra' => '^1.0'],
            ],
            json_decode((string) file_get_contents($this->targetDirectory.'/composer.json'), true),
        );
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_adds_the_php_pin_to_a_manifest_written_before_it_existed(): void
    {
        $this->filesystem->dumpFile($this->targetDirectory.'/composer.json', '{"name":"acme/app"}');

        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess(), platformPhpVersion: '8.3.99'))->install('anthropic', $this->targetDirectory);

        self::assertSame(
            ['name' => 'acme/app', 'config' => ['platform' => ['php' => '8.3.99']]],
            json_decode((string) file_get_contents($this->targetDirectory.'/composer.json'), true),
        );
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_refuses_a_manifest_it_cannot_read(): void
    {
        $this->filesystem->mkdir($this->targetDirectory.'/composer.json');

        $this->expectException(BridgeInstallationFailedException::class);
        $this->expectExceptionMessage('File is a directory');

        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess()))->install('anthropic', $this->targetDirectory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_refuses_a_manifest_it_cannot_parse(): void
    {
        $this->filesystem->dumpFile($this->targetDirectory.'/composer.json', '{not json');

        $this->expectException(BridgeInstallationFailedException::class);
        $this->expectExceptionMessage('composer.json');

        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess()))->install('anthropic', $this->targetDirectory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_refuses_a_manifest_that_is_not_a_json_object(): void
    {
        $this->filesystem->dumpFile($this->targetDirectory.'/composer.json', '"just a string"');

        $this->expectException(BridgeInstallationFailedException::class);
        $this->expectExceptionMessage('not a JSON object');

        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess()))->install('anthropic', $this->targetDirectory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    #[DataProvider('providerPackageCases')]
    public function test_it_requires_the_provider_specific_bridge_package(string $provider, string $expectedPackage): void
    {
        $captured = [];
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static function (string $package, ?string $aiPlatformPin, string $targetDirectory) use (&$captured): Process {
            $captured[] = [$package, $aiPlatformPin];

            return new Process(['true']);
        });

        $composerBridgeInstaller->install($provider, $this->targetDirectory);

        self::assertSame([[$expectedPackage, null]], $captured);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_requires_every_bridge_it_is_given_in_a_single_composer_run(): void
    {
        $captured = [];
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static function (string $package, ?string $aiPlatformPin, string $targetDirectory, string ...$morePackages) use (&$captured): Process {
            $captured[] = [[$package, ...$morePackages], $aiPlatformPin];

            return new Process(['true']);
        }, aiPlatformPin: 'v0.14.1');

        $composerBridgeInstaller->install('bedrock.prod', $this->targetDirectory, 'generic');

        self::assertSame([[['symfony/ai-bedrock-platform', 'symfony/ai-generic-platform'], 'v0.14.1']], $captured);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_a_failed_run_names_every_bridge_it_was_installing(): void
    {
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static fn (string $package, ?string $aiPlatformPin, string $targetDirectory, string ...$morePackages): Process => new Process(['false']));

        $this->expectException(BridgeInstallationFailedException::class);
        $this->expectExceptionMessage('"symfony/ai-bedrock-platform", "symfony/ai-generic-platform"');

        $composerBridgeInstaller->install('bedrock', $this->targetDirectory, 'generic');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function providerPackageCases(): iterable
    {
        yield 'minimax hyphenates as mini-max' => ['minimax', 'symfony/ai-mini-max-platform'];
        yield 'lmstudio hyphenates as lm-studio' => ['lmstudio', 'symfony/ai-lm-studio-platform'];
        yield 'openrouter hyphenates as open-router' => ['openrouter', 'symfony/ai-open-router-platform'];
        yield 'dockermodelrunner hyphenates as docker-model-runner' => ['dockermodelrunner', 'symfony/ai-docker-model-runner-platform'];
        yield 'transformersphp hyphenates as transformers-php' => ['transformersphp', 'symfony/ai-transformers-php-platform'];
        yield 'verbatim slug' => ['gemini', 'symfony/ai-gemini-platform'];
        yield 'openai maps to the hyphenated open-ai package' => ['openai', 'symfony/ai-open-ai-platform'];
        yield 'deepseek maps to the hyphenated deep-seek package' => ['deepseek', 'symfony/ai-deep-seek-platform'];
        yield 'vertexai maps to the hyphenated vertex-ai package' => ['vertexai', 'symfony/ai-vertex-ai-platform'];
        yield 'an instance-keyed provider installs the bridge of its platform' => ['generic.my_gateway', 'symfony/ai-generic-platform'];
        yield 'an instance-keyed provider still honours the slug overrides' => ['openresponses.my_gateway', 'symfony/ai-open-responses-platform'];
    }

    public function test_every_platform_resolves_to_the_bridge_package_the_bundle_requires(): void
    {
        preg_match_all(
            '/if \(\x27([a-z]+)\x27 === \$type\) \{\s+if \(!ContainerBuilder::willBeAvailable\(\x27(symfony\/ai-[a-z-]+-platform)\x27/',
            (string) file_get_contents(self::AI_BUNDLE_CLASS),
            $matches,
            \PREG_SET_ORDER,
        );

        $required = [];
        $resolved = [];
        foreach ($matches as [, $platform, $package]) {
            $required[$platform] = $package;
            $resolved[$platform] = ComposerBridgeInstaller::packageFor($platform);
        }

        self::assertArrayHasKey('anthropic', $required);
        self::assertSame($required, $resolved);
    }

    public function test_every_slug_override_is_its_config_key_with_hyphens_inserted(): void
    {
        $slugs = ComposerBridgeInstaller::PACKAGE_SLUG_OVERRIDES;

        self::assertSame(
            array_keys($slugs),
            array_map(static fn (string $slug): string => str_replace('-', '', $slug), array_values($slugs)),
        );
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_throws_when_the_install_process_fails(): void
    {
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static fn (string $package, ?string $aiPlatformPin, string $targetDirectory): Process => new Process(['false']));

        $this->expectException(BridgeInstallationFailedException::class);
        $this->expectExceptionMessage('symfony/ai-anthropic-platform');

        $composerBridgeInstaller->install('anthropic', $this->targetDirectory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_the_failure_message_carries_the_composer_error_output(): void
    {
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static fn (string $package, ?string $aiPlatformPin, string $targetDirectory): Process => Process::fromShellCommandline('echo "network unreachable" 1>&2; exit 1'));

        $this->expectException(BridgeInstallationFailedException::class);
        $this->expectExceptionMessage('network unreachable');

        $composerBridgeInstaller->install('anthropic', $this->targetDirectory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_throws_when_composer_cannot_be_started(): void
    {
        $unlaunchableWorkingDirectory = $this->targetDirectory.'/missing-'.bin2hex(random_bytes(4));
        $composerBridgeInstaller = new ComposerBridgeInstaller(processBuilder: static fn (string $package, ?string $aiPlatformPin, string $targetDirectory): Process => new Process(['true'], $unlaunchableWorkingDirectory));

        $this->expectException(BridgeInstallationFailedException::class);
        $this->expectExceptionMessage('composer');

        $composerBridgeInstaller->install('anthropic', $this->targetDirectory);
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_default_process_builder_uses_composer_require_in_the_target_directory(): void
    {
        $process = (ComposerBridgeInstaller::defaultProcessBuilder())('symfony/ai-anthropic-platform', 'v0.14.1', '/data/bridges');

        $commandLine = $process->getCommandLine();
        self::assertStringContainsString("'composer'", $commandLine);
        self::assertStringContainsString("'require'", $commandLine);
        self::assertStringContainsString("'symfony/ai-anthropic-platform' 'symfony/ai-platform:v0.14.1'", $commandLine);
        self::assertStringContainsString("'--working-dir=/data/bridges'", $commandLine);
        self::assertStringContainsString("'--no-interaction'", $commandLine);
        self::assertNull($process->getTimeout());
    }

    /**
     * @return Closure(string, ?string, string): Process
     */
    private function succeedingProcess(): Closure
    {
        return static fn (string $package, ?string $aiPlatformPin, string $targetDirectory): Process => new Process(['true']);
    }

    public function test_default_process_builder_requires_every_package_before_the_platform_pin(): void
    {
        $process = (ComposerBridgeInstaller::defaultProcessBuilder())('symfony/ai-bedrock-platform', 'v0.14.1', '/data/bridges', 'symfony/ai-generic-platform');

        self::assertStringContainsString("'require' 'symfony/ai-bedrock-platform' 'symfony/ai-generic-platform' 'symfony/ai-platform:v0.14.1'", $process->getCommandLine());
    }

    public function test_default_process_builder_names_no_platform_pin_when_there_is_none(): void
    {
        $process = (ComposerBridgeInstaller::defaultProcessBuilder())('symfony/ai-anthropic-platform', null, '/data/bridges');

        self::assertStringContainsString("'require' 'symfony/ai-anthropic-platform' '--working-dir=/data/bridges'", $process->getCommandLine());
    }

    #[DataProvider('providerPackageCases')]
    public function test_platform_for_slug_reverses_package_for(string $provider, string $expectedPackage): void
    {
        $slug = substr($expectedPackage, \strlen('symfony/ai-'), -\strlen('-platform'));

        self::assertSame(ProviderKey::of($provider)->platform, ComposerBridgeInstaller::platformForSlug($slug));
    }

    /**
     * @throws BridgeInstallationFailedException
     */
    public function test_it_preserves_an_empty_json_object_in_an_existing_manifest(): void
    {
        $this->filesystem->dumpFile($this->targetDirectory.'/composer.json', '{"name":"acme/app","config":{"allow-plugins":{}}}');

        (new ComposerBridgeInstaller(processBuilder: $this->succeedingProcess(), platformPhpVersion: '8.3.99'))->install('anthropic', $this->targetDirectory);

        $written = (string) file_get_contents($this->targetDirectory.'/composer.json');
        self::assertStringContainsString('"allow-plugins": {}', $written);
        self::assertStringNotContainsString('"allow-plugins": []', $written);
    }
}
