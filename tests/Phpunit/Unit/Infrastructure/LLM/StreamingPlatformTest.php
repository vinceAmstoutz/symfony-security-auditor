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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Test\MockPlatformFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\StreamingPlatform;

final class StreamingPlatformTest extends TestCase
{
    public function test_it_lists_the_models_of_the_platform_it_streams(): void
    {
        $platform = MockPlatformFactory::createPlatform('answer');

        self::assertSame($platform->getModelCatalog(), (new StreamingPlatform($platform))->getModelCatalog());
    }
}
