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
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\SymfonyProjectFile;

final class NullCodeSlicerTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_original_content_unchanged(): void
    {
        $content = "<?php\nclass Foo { /* … */ }";
        $projectFile = SymfonyProjectFile::create('src/Foo.php', '/app/src/Foo.php', $content);

        self::assertSame($content, (new NullCodeSlicer())->slice($projectFile));
    }
}
