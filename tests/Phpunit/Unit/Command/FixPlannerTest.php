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

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InvalidProjectPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FixPlanner;
use VinceAmstoutz\SymfonySecurityAuditor\Command\SuggestedFix;

final class FixPlannerTest extends TestCase
{
    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/fix_planner_test_'.uniqid('', true);
        (new Filesystem())->dumpFile($this->tmpDir.'/src/Repo.php', "a\n");
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmpDir);
    }

    /**
     * @throws InvalidProjectPathException
     */
    public function test_a_fix_for_a_file_it_cannot_read_is_refused(): void
    {
        $filesystem = self::createStub(Filesystem::class);
        $filesystem->method('readFile')->willThrowException(new IOException('Permission denied'));

        $fixPlan = (new FixPlanner($filesystem))->plan([new SuggestedFix('t', 'src/Repo.php', "--- a/src/Repo.php\n+++ b/src/Repo.php\n@@ -1 +1 @@\n-a\n+b")], $this->tmpDir);

        self::assertSame([0, []], [$fixPlan->appliedCount(), $fixPlan->contents]);
    }
}
