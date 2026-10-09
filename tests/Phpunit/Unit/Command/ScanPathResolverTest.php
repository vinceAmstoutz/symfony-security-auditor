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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ScanPathOutsideProjectException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ScanPathResolver;

final class ScanPathResolverTest extends TestCase
{
    /**
     * @param list<string> $scanPaths
     * @param list<string> $expected
     *
     * @throws ScanPathOutsideProjectException
     */
    #[DataProvider('resolvableCases')]
    public function test_a_scan_path_is_made_relative_to_the_project_root(array $scanPaths, string $projectPath, array $expected): void
    {
        self::assertSame($expected, ScanPathResolver::resolve($scanPaths, $projectPath));
    }

    /**
     * @return iterable<string, array{list<string>, string, list<string>}>
     */
    public static function resolvableCases(): iterable
    {
        yield 'a relative path is kept as given' => [['src/Command'], 'C:/Users/vince/demo', ['src/Command']];
        yield 'no path at all' => [[], '/home/vince/demo', []];
        yield 'a relative path holding a drive-like segment' => [['src/C:/odd'], '/home/vince/demo', ['src/C:/odd']];
        yield 'an absolute POSIX path inside the project' => [['/home/vince/demo/src/Command'], '/home/vince/demo', ['src/Command']];
        yield 'an absolute Windows path with backslashes' => [['C:\Users\vince\demo\src\Command'], 'C:/Users/vince/demo', ['src/Command']];
        yield 'an absolute Windows path with forward slashes' => [['C:/Users/vince/demo/src/Command'], 'C:/Users/vince/demo', ['src/Command']];
        yield 'a Windows drive letter in lower case' => [['c:\Users\vince\demo\src'], 'C:/Users/vince/demo', ['src']];
        yield 'a trailing separator' => [['/home/vince/demo/src/'], '/home/vince/demo', ['src']];
        yield 'a dot segment resolved inside the project' => [['/home/vince/demo/src/../config'], '/home/vince/demo', ['config']];
        yield 'the project root itself means the whole project' => [['/home/vince/demo'], '/home/vince/demo', []];
        yield 'several paths, mixed' => [['src/Entity', '/home/vince/demo/templates'], '/home/vince/demo', ['src/Entity', 'templates']];
        yield 'a decomposed accent in the project path against a precomposed one in the scan path' => [["/home/jos\u{E9}/proj/src"], "/home/jose\u{301}/proj", ['src']];
    }

    /**
     * @param list<string> $scanPaths
     * @param list<string> $expected
     *
     * @throws ScanPathOutsideProjectException
     */
    #[DataProvider('pathsUnderAProjectThatIsNotUtf8')]
    public function test_a_project_path_that_is_not_valid_utf8_does_not_keep_the_scan_paths_from_resolving(array $scanPaths, string $projectPath, array $expected): void
    {
        self::assertSame($expected, ScanPathResolver::resolve($scanPaths, $projectPath));
    }

    /**
     * @return iterable<string, array{list<string>, string, list<string>}>
     */
    public static function pathsUnderAProjectThatIsNotUtf8(): iterable
    {
        yield 'no path at all' => [[], "/home/jos\xE9/proj", []];
        yield 'a relative path' => [['src'], "/home/jos\xE9/proj", ['src']];
        yield 'an absolute path inside the project' => [["/home/jos\xE9/proj/src"], "/home/jos\xE9/proj", ['src']];
        yield 'an absolute path whose own name is not valid UTF-8' => [["/home/jos\xE9/proj/src/caf\xE9"], "/home/jos\xE9/proj", ["src/caf\xE9"]];
        yield 'a backslash separated path inside the project' => [["/home/jos\xE9/proj\\src"], "/home/jos\xE9/proj", ['src']];
    }

    /**
     * @throws ScanPathOutsideProjectException
     */
    public function test_an_absolute_scan_path_outside_a_project_that_is_not_valid_utf8_is_refused(): void
    {
        $this->expectException(ScanPathOutsideProjectException::class);

        ScanPathResolver::resolve(['/somewhere/else'], "/home/jos\xE9/proj");
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws ScanPathOutsideProjectException
     */
    #[DataProvider('pathsOutsideTheProject')]
    public function test_an_absolute_scan_path_outside_the_project_is_refused_naming_both(array $scanPaths, string $projectPath): void
    {
        $this->expectException(ScanPathOutsideProjectException::class);
        $this->expectExceptionMessage(\sprintf('The --path "%s" lies outside the project "%s"', $scanPaths[0], $projectPath));

        ScanPathResolver::resolve($scanPaths, $projectPath);
    }

    /**
     * @return iterable<string, array{list<string>, string}>
     */
    public static function pathsOutsideTheProject(): iterable
    {
        yield 'another directory' => [['/somewhere/else'], '/home/vince/demo'];
        yield 'a sibling that merely shares the name prefix' => [['/home/vince/demo-other/src'], '/home/vince/demo'];
        yield 'a dot-dot segment leaving the project' => [['/home/vince/demo/../other'], '/home/vince/demo'];
        yield 'another Windows drive' => [['D:\work\src'], 'C:/Users/vince/demo'];
    }

    /**
     * @throws ScanPathOutsideProjectException
     */
    public function test_the_refusal_says_to_give_the_path_relative_to_the_project_root(): void
    {
        $this->expectException(ScanPathOutsideProjectException::class);
        $this->expectExceptionMessage('relative to the project root, for example --path src/Controller');

        ScanPathResolver::resolve(['/somewhere/else'], '/home/vince/demo');
    }
}
