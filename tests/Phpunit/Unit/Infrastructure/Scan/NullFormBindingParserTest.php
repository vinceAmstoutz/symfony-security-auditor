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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullFormBindingParser;

final class NullFormBindingParserTest extends TestCase
{
    public function test_it_returns_empty_for_any_controller(): void
    {
        $nullFormBindingParser = new NullFormBindingParser();

        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', '<?php class UserController {}');

        self::assertSame([], $nullFormBindingParser->parse($projectFile));
    }
}
