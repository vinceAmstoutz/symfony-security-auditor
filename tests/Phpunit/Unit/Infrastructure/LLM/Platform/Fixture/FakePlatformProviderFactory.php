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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Platform\Fixture;

use Symfony\AI\Platform\PlatformInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\PlatformConnection;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\PlatformProviderFactoryInterface;

final readonly class FakePlatformProviderFactory implements PlatformProviderFactoryInterface
{
    public function __construct(
        private string $provider,
        private PlatformInterface $platform,
    ) {}

    public function provider(): string
    {
        return $this->provider;
    }

    public function create(PlatformConnection $platformConnection): PlatformInterface
    {
        return $this->platform;
    }
}
