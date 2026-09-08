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
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\NullAuthorizationRuleParser;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\SymfonyProjectFile;

final class NullAuthorizationRuleParserTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_null_for_any_voter(): void
    {
        $nullAuthorizationRuleParser = new NullAuthorizationRuleParser();

        $projectFile = SymfonyProjectFile::create('src/Security/UserVoter.php', '/app/x', '<?php class UserVoter {}');

        self::assertNull($nullAuthorizationRuleParser->parse($projectFile));
    }
}
