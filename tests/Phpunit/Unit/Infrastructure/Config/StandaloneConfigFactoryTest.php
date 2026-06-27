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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFactory;

final class StandaloneConfigFactoryTest extends TestCase
{
    public function test_it_builds_the_rootless_config_with_an_env_referenced_api_key(): void
    {
        self::assertSame(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4'],
            (new StandaloneConfigFactory())->create('openai', 'gpt-5.4', 'OPENAI_API_KEY'),
        );
    }
}
