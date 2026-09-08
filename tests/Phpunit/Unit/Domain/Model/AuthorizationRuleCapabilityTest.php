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
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AuthorizationRuleCapability;

final class AuthorizationRuleCapabilityTest extends TestCase
{
    public function test_it_exposes_file_path_class_name_attributes_and_subjects(): void
    {
        $authorizationRuleCapability = new AuthorizationRuleCapability(
            filePath: 'src/Security/UserVoter.php',
            className: 'App\\Security\\UserVoter',
            supportedAttributes: ['EDIT', 'DELETE'],
            supportedSubjects: ['App\\Entity\\User'],
        );

        self::assertSame('src/Security/UserVoter.php', $authorizationRuleCapability->filePath());
        self::assertSame('App\\Security\\UserVoter', $authorizationRuleCapability->className());
        self::assertSame(['EDIT', 'DELETE'], $authorizationRuleCapability->supportedAttributes());
        self::assertSame(['App\\Entity\\User'], $authorizationRuleCapability->supportedSubjects());
    }

    public function test_covers_attribute_returns_true_for_supported_attribute(): void
    {
        $authorizationRuleCapability = new AuthorizationRuleCapability('src/Security/V.php', 'V', ['EDIT'], []);

        self::assertTrue($authorizationRuleCapability->coversAttribute('EDIT'));
        self::assertFalse($authorizationRuleCapability->coversAttribute('DELETE'));
    }

    public function test_covers_subject_matches_by_short_name_or_full_class_name(): void
    {
        $authorizationRuleCapability = new AuthorizationRuleCapability('src/Security/V.php', 'V', [], ['App\\Entity\\User']);

        self::assertTrue($authorizationRuleCapability->coversSubject('App\\Entity\\User'));
        self::assertTrue($authorizationRuleCapability->coversSubject('User'));
        self::assertFalse($authorizationRuleCapability->coversSubject('Comment'));
    }
}
