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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullCodeSlicer;

final class NullCodeSlicerTest extends TestCase
{
    public function test_it_returns_original_content_unchanged(): void
    {
        $content = "<?php\nclass Foo { /* … */ }";
        $projectFile = ProjectFile::create('src/Foo.php', '/app/src/Foo.php', $content);

        self::assertSame($content, (new NullCodeSlicer())->slice($projectFile));
    }
}
