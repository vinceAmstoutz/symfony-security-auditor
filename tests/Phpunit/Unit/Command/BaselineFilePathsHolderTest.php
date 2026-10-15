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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineFilePathsHolder;

final class BaselineFilePathsHolderTest extends TestCase
{
    public function test_it_names_no_file_before_a_run_hands_it_the_baseline(): void
    {
        self::assertSame([], (new BaselineFilePathsHolder())->naming('src/A.php'));
    }

    public function test_it_names_a_file_by_every_baseline_path_that_denotes_it_in_the_project_in_baseline_order(): void
    {
        $baselineFilePathsHolder = new BaselineFilePathsHolder();
        $baselineFilePathsHolder->set('/abs/project', [
            './src/A.php',
            'src/B.php',
            'src\A.php',
            '/elsewhere/src/A.php',
            '/abs/project/src/A.php',
            'lib/src/A.php',
            '/src/A.php',
            'src/A.php',
        ]);

        self::assertSame(
            [['./src/A.php', 'src\A.php', '/abs/project/src/A.php', '/src/A.php', 'src/A.php'], ['src/B.php']],
            [$baselineFilePathsHolder->naming('src/A.php'), $baselineFilePathsHolder->naming('src/B.php')],
        );
    }

    public function test_a_later_run_replaces_the_baseline_and_the_project_of_the_one_before(): void
    {
        $baselineFilePathsHolder = new BaselineFilePathsHolder();
        $baselineFilePathsHolder->set('/abs/project', ['./src/A.php', '/abs/project/src/A.php']);
        $baselineFilePathsHolder->set('/other/project', ['/abs/project/src/A.php', '/other/project/src/A.php']);

        self::assertSame(['/other/project/src/A.php'], $baselineFilePathsHolder->naming('src/A.php'));
    }
}
