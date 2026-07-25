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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Configuration;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\PrivacyConfiguration;

final class PrivacyConfigurationTest extends TestCase
{
    public function test_offline_only_is_opt_in(): void
    {
        self::assertFalse((new PrivacyConfiguration())->offlineOnly);
    }

    public function test_offline_only_can_be_turned_on(): void
    {
        self::assertTrue((new PrivacyConfiguration(offlineOnly: true))->offlineOnly);
    }
}
