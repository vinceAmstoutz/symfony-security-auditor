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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullEntrypointAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\SymfonyProjectFile;

final class NullEntrypointAccessControlParserTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_empty_for_any_controller(): void
    {
        $nullEntrypointAccessControlParser = new NullEntrypointAccessControlParser();

        $projectFile = SymfonyProjectFile::create('src/Controller/AdminController.php', '/app/x', '<?php class AdminController {}');

        self::assertSame([], $nullEntrypointAccessControlParser->parse($projectFile));
    }
}
