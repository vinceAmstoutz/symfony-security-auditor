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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullVoterCapabilityParser;

final class NullVoterCapabilityParserTest extends TestCase
{
    public function test_it_returns_null_for_any_voter(): void
    {
        $nullVoterCapabilityParser = new NullVoterCapabilityParser();

        $projectFile = ProjectFile::create('src/Security/UserVoter.php', '/app/x', '<?php class UserVoter {}');

        self::assertNull($nullVoterCapabilityParser->parse($projectFile));
    }
}
