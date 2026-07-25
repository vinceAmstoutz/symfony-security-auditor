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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class NonLocalPlatformEndpointException extends RuntimeException
{
    public static function forProvider(string $provider, string $endpoint): self
    {
        return new self(\sprintf(
            'privacy.offline_only is enabled, but the "%s" platform would send your source code to "%s", which is not a loopback or private-range address. Point it at a local platform (e.g. Ollama on http://localhost:11434) or disable privacy.offline_only.',
            $provider,
            $endpoint,
        ));
    }

    public static function forProviderWithoutEndpoint(string $provider): self
    {
        return new self(\sprintf(
            'privacy.offline_only is enabled, but the "%s" platform is a hosted provider with no local endpoint configured, so every prompt would leave this machine. Configure a local platform (e.g. Ollama on http://localhost:11434) or disable privacy.offline_only.',
            $provider,
        ));
    }
}
