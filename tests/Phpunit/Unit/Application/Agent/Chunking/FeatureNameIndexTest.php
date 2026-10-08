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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunking;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FeatureNameIndex;

final class FeatureNameIndexTest extends TestCase
{
    /**
     * @param list<string> $expected
     */
    #[DataProvider('baseNameCases')]
    public function test_it_lists_the_features_a_base_name_starts_with(string $baseName, array $expected): void
    {
        $featureNameIndex = FeatureNameIndex::of(['User', 'UserProfile', 'Post', 'A']);

        self::assertSame($expected, $featureNameIndex->startingBaseName($baseName));
    }

    /** @return iterable<string, array{string, list<string>}> */
    public static function baseNameCases(): iterable
    {
        yield 'a base name that is a feature' => ['User', ['User']];
        yield 'a base name starting with two features' => ['UserProfileEdit', ['User', 'UserProfile']];
        yield 'a feature of one character' => ['AFoo', ['A']];
        yield 'a feature that stops mid-word' => ['Username', ['User']];
        yield 'a base name no feature starts' => ['Other', []];
        yield 'a feature that only appears later in the base name' => ['MyUser', []];
        yield 'a feature of another case' => ['user', []];
        yield 'an empty base name' => ['', []];
    }

    /**
     * @param list<string> $expected
     */
    #[DataProvider('pathCases')]
    public function test_it_lists_the_features_a_directory_of_the_path_is_named_after(string $relativePath, array $expected): void
    {
        $featureNameIndex = FeatureNameIndex::of(['User', 'Post']);

        self::assertSame($expected, $featureNameIndex->namedByDirectory($relativePath));
    }

    /** @return iterable<string, array{string, list<string>}> */
    public static function pathCases(): iterable
    {
        yield 'a directory named after a feature' => ['src/User/Thing.php', ['User']];
        yield 'a directory of another case' => ['templates/user/index.html.twig', ['User']];
        yield 'two directories in path order' => ['src/Post/User/Shared.php', ['Post', 'User']];
        yield 'a directory deep in the path' => ['a/b/User/c/d.php', ['User']];
        yield 'the first segment of the path' => ['User/Thing.php', []];
        yield 'the file name' => ['docs/user', []];
        yield 'a directory that only contains the feature' => ['src/MyUser/Thing.php', []];
        yield 'a directory that only starts with the feature' => ['src/username/Other.php', []];
        yield 'a file at the project root' => ['Thing.php', []];
    }

    /**
     * @param list<string> $features
     */
    #[DataProvider('specificityCases')]
    public function test_it_picks_the_longest_feature_then_the_first_declared(array $features, ?string $expected): void
    {
        $featureNameIndex = FeatureNameIndex::of(['User', 'Post', 'UserProfile']);

        self::assertSame($expected, $featureNameIndex->mostSpecific($features));
    }

    /** @return iterable<string, array{list<string>, ?string}> */
    public static function specificityCases(): iterable
    {
        yield 'no feature' => [[], null];
        yield 'a single feature' => [['Post'], 'Post'];
        yield 'the longer feature first' => [['UserProfile', 'User'], 'UserProfile'];
        yield 'the longer feature last' => [['User', 'UserProfile'], 'UserProfile'];
        yield 'equally long features, the first declared met first' => [['User', 'Post'], 'User'];
        yield 'equally long features, the first declared met last' => [['Post', 'User'], 'User'];
        yield 'the same feature twice' => [['Post', 'Post'], 'Post'];
    }
}
