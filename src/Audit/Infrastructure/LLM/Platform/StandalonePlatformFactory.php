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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform;

use Symfony\AI\Platform\PlatformInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\Exception\UnsupportedPlatformProviderException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandalonePlatformFactory
{
    /**
     * @param iterable<PlatformProviderFactoryInterface> $providerFactories
     */
    public function __construct(
        private iterable $providerFactories,
    ) {}

    public function create(PlatformConnection $platformConnection): PlatformInterface
    {
        $supportedProviders = [];

        foreach ($this->providerFactories as $providerFactory) {
            if ($providerFactory->provider() === $platformConnection->provider) {
                return $providerFactory->create($platformConnection);
            }

            $supportedProviders[] = $providerFactory->provider();
        }

        throw UnsupportedPlatformProviderException::forProvider($platformConnection->provider, $supportedProviders);
    }
}
