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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProductionConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\KernelConfigurationLoader;

final class KernelConfigurationLoaderTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_loads_the_packages_then_the_production_packages_in_path_order(): void
    {
        self::assertSame([
            'config/packages/framework.yaml',
            'config/packages/security.yml',
            'config/packages/prod/a.yaml',
            'config/packages/prod/nested/b.yaml',
        ], $this->loadedPaths([
            'config/packages/security.yml' => '',
            'config/packages/prod/nested/b.yaml' => '',
            'src/Controller/HomeController.php' => '',
            'config/packages/framework.yaml' => '',
            'config/packages/prod/a.yaml' => '',
            'config/packages/dev/debug.yaml' => '',
            'config/packages/test/security.yaml' => '',
            'config/packages/security.xml' => '',
            'config/packages/security.yaml.dist' => '',
            'config/legacy/access.yaml' => '',
            'config/services.yaml' => '',
        ]));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_loads_a_file_after_the_files_it_imports_and_each_file_once(): void
    {
        self::assertSame([
            'config/security/firewalls.yaml',
            'config/packages/security.yaml',
            'config/security/access_control.yaml',
            'config/packages/a.yaml',
        ], $this->loadedPaths([
            'config/packages/a.yaml' => "imports:\n    - '../security/access_control.yaml'\n",
            'config/packages/security.yaml' => "imports:\n    - '../security/*.yaml'\n    - 'a.yaml'\n",
            'config/security/access_control.yaml' => "imports:\n    - 'firewalls.yaml'\n    - '../packages/security.yaml'\n",
            'config/security/firewalls.yaml' => '',
        ]));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_never_loads_an_imported_file_that_is_not_yaml(): void
    {
        self::assertSame(['config/security/rules.yml', 'config/packages/security.yaml'], $this->loadedPaths([
            'config/packages/security.yaml' => "imports:\n    - '../security/*'\n",
            'config/security/rules.php' => "security:\n    access_control: []\n",
            'config/security/rules.xml' => "security:\n    access_control: []\n",
            'config/security/rules.yml' => '',
        ]));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_follows_imports_eight_levels_deep(): void
    {
        $files = ['config/packages/security.yaml' => "imports:\n    - '../imported/1.yaml'\n"];
        foreach (range(1, 9) as $level) {
            $files[\sprintf('config/imported/%d.yaml', $level)] = \sprintf("imports:\n    - '%d.yaml'\n", $level + 1);
        }

        $productionConfiguration = $this->productionConfigurationOf($files);

        self::assertSame(['config/imported/9.yaml' => 'it is imported more than 8 levels deep'], $productionConfiguration->unreadableFiles);
        self::assertSame([
            'config/imported/8.yaml',
            'config/imported/7.yaml',
            'config/imported/6.yaml',
            'config/imported/5.yaml',
            'config/imported/4.yaml',
            'config/imported/3.yaml',
            'config/imported/2.yaml',
            'config/imported/1.yaml',
            'config/packages/security.yaml',
        ], $this->pathsOf($productionConfiguration->projectFiles));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_reads_128_configuration_files_and_reports_the_others(): void
    {
        $files = [];
        foreach (range(1, 130) as $index) {
            $files[\sprintf('config/packages/p%03d.yaml', $index)] = 129 === $index ? "security: ~\n" : '';
        }

        $productionConfiguration = $this->productionConfigurationOf($files);

        self::assertSame(\array_slice(array_keys($files), 0, 128), $this->pathsOf($productionConfiguration->projectFiles));
        self::assertSame(['config/packages/p129.yaml' => 'the audit reads at most 128 configuration files'], $productionConfiguration->unreadableFiles);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_reads_two_mebibytes_of_configuration_and_reports_the_rest(): void
    {
        $files = [];
        foreach (range(1, 8) as $index) {
            $files[\sprintf('config/packages/p%d.yaml', $index)] = '#'.str_repeat('x', 262_142)."\n";
        }

        $files['config/packages/p9.yaml'] = "security: ~\n";
        $files['config/packages/prod/p10.yaml'] = '';

        $productionConfiguration = $this->productionConfigurationOf($files);

        self::assertSame([...\array_slice(array_keys($files), 0, 8), 'config/packages/prod/p10.yaml'], $this->pathsOf($productionConfiguration->projectFiles));
        self::assertSame(['config/packages/p9.yaml' => 'the audit reads at most 2097152 bytes of configuration'], $productionConfiguration->unreadableFiles);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_reports_a_file_it_cannot_read_and_follows_none_of_its_imports(): void
    {
        $productionConfiguration = $this->productionConfigurationOf([
            'config/packages/security.yaml' => "imports:\n    - 'security/firewalls.yaml'\nsecurity: [\n",
            'config/packages/security/firewalls.yaml' => '',
            'config/packages/zz.yaml' => "imports:\n".str_repeat("    - 'security/firewalls.yaml'\n", 33),
        ]);

        self::assertSame([], $productionConfiguration->projectFiles);
        self::assertSame(['config/packages/security.yaml', 'config/packages/zz.yaml'], array_keys($productionConfiguration->unreadableFiles));
        self::assertStringStartsWith('it is not valid YAML: ', $productionConfiguration->unreadableFiles['config/packages/security.yaml']);
        self::assertSame('it imports 33 resources, more than the 32 the audit follows', $productionConfiguration->unreadableFiles['config/packages/zz.yaml']);
    }

    /**
     * @param list<string> $expectedUnreadable
     *
     * @throws InvalidProjectFileException
     */
    #[DataProvider('unreadableFileCases')]
    public function test_it_reports_a_file_it_cannot_read_only_when_it_may_hold_security_configuration(string $content, array $expectedUnreadable): void
    {
        self::assertSame($expectedUnreadable, array_keys($this->productionConfigurationOf(['config/packages/app.yaml' => $content.'#'.str_repeat('x', 262_144)."\n"])->unreadableFiles));
    }

    /** @return iterable<string, array{0: string, 1: list<string>}> */
    public static function unreadableFileCases(): iterable
    {
        yield 'a security block' => ["security:\n    firewalls: ~\n", ['config/packages/app.yaml']];
        yield 'a production block' => ["when@prod:\n    framework: ~\n", ['config/packages/app.yaml']];
        yield 'imports' => ["imports: []\n", ['config/packages/app.yaml']];
        yield 'a bare access control list' => ["access_control: []\n", ['config/packages/app.yaml']];
        yield 'bare firewalls' => ["firewalls: ~\n", ['config/packages/app.yaml']];
        yield 'a security key followed by blanks' => ["security \t: ~\n", ['config/packages/app.yaml']];
        yield 'a security block after another one' => ["framework: ~\nsecurity: ~\n", ['config/packages/app.yaml']];
        yield 'an API documentation' => ["nelmio_api_doc:\n    documentation: ~\n", []];
        yield 'a nested security key' => ["framework:\n    security: ~\n", []];
        yield 'a key that only starts like security' => ["security_extra: ~\n", []];
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_parses_a_package_file_holding_custom_tags(): void
    {
        $productionConfiguration = $this->productionConfigurationOf([
            'config/packages/messenger.yaml' => "framework:\n    messenger: ~\nservices:\n    App\\Handler\\Chain:\n        arguments: [!tagged_iterator app.handler]\n",
        ]);

        self::assertSame(['config/packages/messenger.yaml'], $this->pathsOf($productionConfiguration->projectFiles));
        self::assertSame([], $productionConfiguration->unreadableFiles);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_each_application_reads_its_own_files_and_those_it_shares_with_the_project(): void
    {
        $productionConfiguration = $this->productionConfigurationOf([
            'config/packages/security.yaml' => "imports:\n    - '../../shared/security.yaml'\n",
            'apps/api/config/packages/security.yaml' => "imports:\n    - '../../../../shared/security.yaml'\n",
            'apps/api/config/packages/prod/security.yaml' => '',
            'shared/security.yaml' => '',
        ], ['apps/api']);

        self::assertSame(['shared/security.yaml', 'config/packages/security.yaml'], $this->pathsOf($productionConfiguration->projectFiles));
        self::assertSame(['apps/api/'], array_keys($productionConfiguration->applicationFiles));
        self::assertSame(['shared/security.yaml', 'apps/api/config/packages/security.yaml', 'apps/api/config/packages/prod/security.yaml'], $this->pathsOf($productionConfiguration->applicationFiles['apps/api/']));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_an_application_without_configuration_of_its_own_leaves_its_routes_to_the_project(): void
    {
        $productionConfiguration = $this->productionConfigurationOf([
            'config/packages/security.yaml' => '',
            'apps/api/src/Controller/HomeController.yaml' => '',
        ], ['apps/api', 'src']);

        self::assertSame([], $productionConfiguration->applicationFiles);
    }

    /**
     * @param array<string, string> $files
     *
     * @return list<string>
     *
     * @throws InvalidProjectFileException
     */
    private function loadedPaths(array $files): array
    {
        $productionConfiguration = $this->productionConfigurationOf($files);
        self::assertSame([], $productionConfiguration->unreadableFiles);

        return $this->pathsOf($productionConfiguration->projectFiles);
    }

    /**
     * @param array<string, string> $files
     * @param list<string>          $scanPaths
     *
     * @throws InvalidProjectFileException
     */
    private function productionConfigurationOf(array $files, array $scanPaths = []): ProductionConfiguration
    {
        $projectFiles = [];
        foreach ($files as $relativePath => $content) {
            $projectFiles[] = ProjectFile::create($relativePath, '/app/'.$relativePath, $content);
        }

        return (new KernelConfigurationLoader())->filesInLoadOrder($projectFiles, $scanPaths);
    }

    /**
     * @param list<ProjectFile> $projectFiles
     *
     * @return list<string>
     */
    private function pathsOf(array $projectFiles): array
    {
        return array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $projectFiles);
    }
}
