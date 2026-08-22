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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Standalone;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplication;

final class StandaloneApplicationTest extends TestCase
{
    public function test_it_appends_the_models_dev_version_to_the_long_version(): void
    {
        $standaloneApplication = new StandaloneApplication('symfony-security-auditor', '1.2.3', '132.0');

        self::assertSame(
            'symfony-security-auditor <info>1.2.3</info> (symfony/models-dev 132.0)',
            $standaloneApplication->getLongVersion(),
        );
    }

    public function test_it_reports_the_configured_short_version(): void
    {
        $standaloneApplication = new StandaloneApplication('symfony-security-auditor', '1.2.3', '132.0');

        self::assertSame('1.2.3', $standaloneApplication->getVersion());
    }
}
