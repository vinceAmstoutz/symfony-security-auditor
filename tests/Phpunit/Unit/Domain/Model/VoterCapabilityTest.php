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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;

final class VoterCapabilityTest extends TestCase
{
    public function test_it_exposes_file_path_class_name_attributes_and_subjects(): void
    {
        $voterCapability = new VoterCapability(
            filePath: 'src/Security/UserVoter.php',
            className: 'App\\Security\\UserVoter',
            supportedAttributes: ['EDIT', 'DELETE'],
            supportedSubjects: ['App\\Entity\\User'],
        );

        self::assertSame('src/Security/UserVoter.php', $voterCapability->filePath());
        self::assertSame('App\\Security\\UserVoter', $voterCapability->className());
        self::assertSame(['EDIT', 'DELETE'], $voterCapability->supportedAttributes());
        self::assertSame(['App\\Entity\\User'], $voterCapability->supportedSubjects());
    }

    public function test_covers_attribute_returns_true_for_supported_attribute(): void
    {
        $voterCapability = new VoterCapability('src/Security/V.php', 'V', ['EDIT'], []);

        self::assertTrue($voterCapability->coversAttribute('EDIT'));
        self::assertFalse($voterCapability->coversAttribute('DELETE'));
    }

    public function test_covers_subject_matches_by_short_name_or_full_class_name(): void
    {
        $voterCapability = new VoterCapability('src/Security/V.php', 'V', [], ['App\\Entity\\User']);

        self::assertTrue($voterCapability->coversSubject('App\\Entity\\User'));
        self::assertTrue($voterCapability->coversSubject('User'));
        self::assertFalse($voterCapability->coversSubject('Comment'));
    }
}
