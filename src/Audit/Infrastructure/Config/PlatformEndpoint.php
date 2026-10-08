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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use Uri\Rfc3986\Uri;

/**
 * The scheme, host and port a platform setting would send a request to. A
 * setting without an authority is no endpoint, and the userinfo, path and
 * query of one never leave this class, since they may hold a credential.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformEndpoint
{
    private function __construct(
        public string $scheme,
        public string $host,
        public ?int $port,
    ) {}

    public static function tryFrom(string $value): ?self
    {
        $uri = Uri::parse($value);
        if (!$uri instanceof Uri) {
            return null;
        }

        $scheme = $uri->getScheme();
        $host = $uri->getHost();

        return null === $scheme || null === $host ? null : new self($scheme, $host, $uri->getPort());
    }

    public function origin(): string
    {
        return \sprintf('%s://%s%s', $this->scheme, $this->host, null === $this->port ? '' : \sprintf(':%d', $this->port));
    }
}
