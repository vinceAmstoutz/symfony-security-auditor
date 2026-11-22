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
 * The scheme, host and port a platform setting sends requests to; a setting
 * without an authority is none. Never exposes the userinfo, path or query,
 * which may hold a credential.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PlatformEndpoint
{
    private const string IPV6_LOOPBACK = '::1';

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
        $host = $uri->getRawHost();

        return null === $scheme || null === $host ? null : new self($scheme, strtolower($host), $uri->getPort());
    }

    /**
     * True for `localhost`, an address of `127.0.0.0/8` or `::1`.
     */
    public function isLoopback(): bool
    {
        $host = trim($this->host, '[]');
        if ('localhost' === $host) {
            return true;
        }

        $packed = inet_pton($host);

        return false !== $packed && (inet_pton(self::IPV6_LOOPBACK) === $packed || (4 === \strlen($packed) && "\x7f" === $packed[0]));
    }

    public function origin(): string
    {
        return \sprintf('%s://%s%s', $this->scheme, $this->host, null === $this->port ? '' : \sprintf(':%d', $this->port));
    }
}
