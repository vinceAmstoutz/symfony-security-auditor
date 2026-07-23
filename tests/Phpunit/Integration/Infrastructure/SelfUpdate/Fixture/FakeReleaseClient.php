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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\SelfUpdate\Fixture;

use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ReleaseClientInterface;

final class FakeReleaseClient implements ReleaseClientInterface
{
    public int $requests = 0;

    /**
     * @param array<string, string> $bodies keyed by URL
     */
    public function __construct(
        private readonly array $bodies,
        private readonly string $downloadPayload = '',
    ) {}

    #[Override]
    public function get(string $url): string
    {
        ++$this->requests;

        return $this->bodies[$url] ?? throw SelfUpdateFailedException::forFailedDownload($url);
    }

    /**
     * @throws SelfUpdateFailedException
     */
    #[Override]
    public function download(string $url, string $destination): void
    {
        ++$this->requests;

        try {
            (new Filesystem())->dumpFile($destination, $this->downloadPayload);
        } catch (IOException $ioException) {
            throw SelfUpdateFailedException::forFailedDownload($url, $ioException);
        }
    }
}
