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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ProjectConfigPathAnchor;

final class ProjectConfigPathAnchorTest extends TestCase
{
    public function test_a_relative_baseline_is_resolved_against_the_folder_of_the_project_config(): void
    {
        $anchored = ProjectConfigPathAnchor::anchored(
            ['model' => 'm', 'audit' => ['baseline' => '.security-baseline.json', 'min_score' => 3]],
            '/work/app/.symfony-security-auditor.yaml',
        );

        self::assertSame(
            ['model' => 'm', 'audit' => ['baseline' => '/work/app/.security-baseline.json', 'min_score' => 3]],
            $anchored,
        );
    }

    public function test_a_baseline_in_a_subfolder_keeps_its_folder(): void
    {
        $anchored = ProjectConfigPathAnchor::anchored(
            ['audit' => ['baseline' => 'config/../ci/baseline.json']],
            '/work/app/.symfony-security-auditor.yaml',
        );

        self::assertSame(['audit' => ['baseline' => '/work/app/ci/baseline.json']], $anchored);
    }

    /**
     * @param array<array-key, mixed> $projectConfig
     */
    #[DataProvider('configsLeftAsWritten')]
    public function test_a_config_without_a_relative_baseline_is_left_as_written(array $projectConfig): void
    {
        self::assertSame(
            $projectConfig,
            ProjectConfigPathAnchor::anchored($projectConfig, '/work/app/.symfony-security-auditor.yaml'),
        );
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function configsLeftAsWritten(): iterable
    {
        yield 'no audit section' => [['model' => 'm']];
        yield 'an audit section without a baseline' => [['audit' => ['min_score' => 3]]];
        yield 'an absolute baseline' => [['audit' => ['baseline' => '/ci/baseline.json']]];
        yield 'a baseline reset to null' => [['audit' => ['baseline' => null]]];
        yield 'an empty baseline' => [['audit' => ['baseline' => '']]];
    }
}
