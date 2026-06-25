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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Platform\Exception;

use InvalidArgumentException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class UnsupportedPlatformProviderException extends InvalidArgumentException
{
    /**
     * @param list<string> $supportedProviders
     */
    public static function forProvider(string $provider, array $supportedProviders): self
    {
        return new self(\sprintf(
            'Unsupported LLM provider "%s". Supported providers: %s.',
            $provider,
            implode(', ', $supportedProviders),
        ));
    }
}
