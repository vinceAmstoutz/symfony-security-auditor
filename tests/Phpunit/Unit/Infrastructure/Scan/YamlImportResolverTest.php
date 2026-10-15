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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\UnreadableYamlException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RepositoryYamlReader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\YamlImportResolver;

final class YamlImportResolverTest extends TestCase
{
    private const string IMPORTING_FILE = 'config/packages/security.yaml';

    /**
     * @param list<string> $expected
     *
     * @throws InvalidProjectFileException
     * @throws UnreadableYamlException
     */
    #[DataProvider('importCases')]
    public function test_it_resolves_the_files_a_configuration_file_imports(string $content, array $expected): void
    {
        self::assertSame($expected, $this->importedPaths($content, [
            'config/packages/security/access_control.yaml',
            'config/packages/security/firewalls.yaml',
            'config/packages/security/sub/deeper.yaml',
            'config/security.yaml',
            'config/packages/framework.yaml',
        ]));
    }

    /** @return iterable<string, array{0: string, 1: list<string>}> */
    public static function importCases(): iterable
    {
        yield 'a file next to it' => ["imports:\n    - { resource: 'framework.yaml' }\n", ['config/packages/framework.yaml']];
        yield 'a file named without a map' => ["imports:\n    - 'security/firewalls.yaml'\n", ['config/packages/security/firewalls.yaml']];
        yield 'a file of the production block' => ["when@prod:\n    imports:\n        - { resource: 'security/firewalls.yaml' }\n", ['config/packages/security/firewalls.yaml']];
        yield 'a file of the root block, then one of the production block' => ["when@prod:\n    imports:\n        - { resource: 'framework.yaml' }\nimports:\n    - { resource: 'security/firewalls.yaml' }\n", ['config/packages/security/firewalls.yaml', 'config/packages/framework.yaml']];
        yield 'the files of imports written as maps under the same key' => ["imports:\n    first: 'security/firewalls.yaml'\nwhen@prod:\n    imports:\n        first: 'framework.yaml'\n", ['config/packages/security/firewalls.yaml', 'config/packages/framework.yaml']];
        yield 'nothing from a test block' => ["when@test:\n    imports:\n        - { resource: 'security/firewalls.yaml' }\n", []];
        yield 'nothing from a development block' => ["when@dev:\n    imports:\n        - { resource: 'security/firewalls.yaml' }\n", []];
        yield 'a file of a parent directory' => ["imports:\n    - { resource: '../security.yaml' }\n", ['config/security.yaml']];
        yield 'the files a wildcard names, in path order' => ["imports:\n    - { resource: 'security/*.yaml' }\n", ['config/packages/security/access_control.yaml', 'config/packages/security/firewalls.yaml']];
        yield 'the files a wildcard between a prefix and a suffix names' => ["imports:\n    - { resource: 'security/fire*.yaml' }\n", ['config/packages/security/firewalls.yaml']];
        yield 'the file a wildcard standing for nothing names' => ["imports:\n    - { resource: 'security/firewalls*.yaml' }\n", ['config/packages/security/firewalls.yaml']];
        yield 'nothing where the suffix of a wildcard differs' => ["imports:\n    - { resource: 'security/access*.yml' }\n", []];
        yield 'nothing where a long prefix of a wildcard overlaps its suffix' => ["imports:\n    - { resource: 'security/firewalls.y*.yaml' }\n", []];
        yield 'nothing where a short prefix of a wildcard overlaps its suffix' => ["imports:\n    - { resource: 'security/fi*irewalls.yaml' }\n", []];
        yield 'the file a wildcard after a one-letter prefix names' => ["imports:\n    - { resource: 'security/f*irewalls.yaml' }\n", ['config/packages/security/firewalls.yaml']];
        yield 'nothing where the prefix and the suffix of a wildcard overlap' => ["imports:\n    - { resource: 'security/firewalls.yaml*firewalls.yaml' }\n", []];
        yield 'nothing for a wildcard folder' => ["imports:\n    - { resource: '*/access_control.yaml' }\n", []];
        yield 'nothing below the directory a wildcard names' => ["imports:\n    - { resource: 'security/sub*' }\n", []];
        yield 'nothing for two wildcards in a name' => ["imports:\n    - { resource: 'security/*_*.yaml' }\n", []];
        yield 'nothing outside the project' => ["imports:\n    - { resource: '../../../security.yaml' }\n", []];
        yield 'nothing for an absolute path' => ["imports:\n    - { resource: '/security/firewalls.yaml' }\n", []];
        yield 'nothing for a resource that is not text' => ["imports:\n    - { resource: ['security/firewalls.yaml'] }\n    - { type: yaml }\n    - 42\n", []];
        yield 'nothing for imports that are not a list' => ["imports: 'security/firewalls.yaml'\n", []];
        yield 'nothing for a document that is a list' => ["- imports\n", []];
    }

    /**
     * @throws InvalidProjectFileException
     * @throws UnreadableYamlException
     */
    public function test_it_follows_thirty_two_imports_of_a_file(): void
    {
        [$imports, $candidates] = $this->importsOf(32);

        self::assertSame($candidates, $this->importedPaths($imports, $candidates));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws UnreadableYamlException
     */
    public function test_it_refuses_a_file_with_more_than_thirty_two_imports(): void
    {
        [$imports, $candidates] = $this->importsOf(33);

        $this->expectException(UnreadableYamlException::class);
        $this->expectExceptionMessage('it imports 33 resources, more than the 32 the audit follows');

        $this->importedPaths($imports, $candidates);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws UnreadableYamlException
     */
    public function test_each_import_looks_among_the_files_of_the_one_folder_it_names(): void
    {
        $lookedUp = [];
        $filesIn = static function (string $folder) use (&$lookedUp): array {
            $lookedUp[] = $folder;

            return [ProjectFile::create($folder.'/firewalls.yaml', '/app/'.$folder.'/firewalls.yaml', '')];
        };
        $content = "imports:\n    - 'security/*.yaml'\n    - '../firewalls.yaml'\n    - 'firewalls.yaml'\n";

        (new YamlImportResolver())->importedFiles(ProjectFile::create(self::IMPORTING_FILE, '/app/'.self::IMPORTING_FILE, $content), (new RepositoryYamlReader())->read($content), $filesIn);

        self::assertSame(['config/packages/security', 'config', 'config/packages'], $lookedUp);
    }

    /**
     * @return array{0: string, 1: list<string>}
     */
    private function importsOf(int $count): array
    {
        $candidates = [];
        $imports = "imports:\n";
        foreach (range(1, $count) as $index) {
            $candidates[] = \sprintf('config/packages/imported/%02d.yaml', $index);
            $imports .= \sprintf("    - 'imported/%02d.yaml'\n", $index);
        }

        return [$imports, $candidates];
    }

    /**
     * @param list<string> $candidates
     *
     * @return list<string>
     *
     * @throws InvalidProjectFileException
     * @throws UnreadableYamlException
     */
    private function importedPaths(string $content, array $candidates): array
    {
        $filesByFolder = [];
        foreach ($candidates as $candidate) {
            $filesByFolder[\dirname($candidate)][] = ProjectFile::create($candidate, '/app/'.$candidate, '');
        }

        $imported = (new YamlImportResolver())->importedFiles(ProjectFile::create(self::IMPORTING_FILE, '/app/'.self::IMPORTING_FILE, $content), (new RepositoryYamlReader())->read($content), static fn (string $folder): array => $filesByFolder[$folder] ?? []);

        return array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $imported);
    }
}
