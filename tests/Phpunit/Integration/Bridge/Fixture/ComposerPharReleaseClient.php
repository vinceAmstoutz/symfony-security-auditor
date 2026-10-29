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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bridge\Fixture;

use Closure;
use Override;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ReleaseClientInterface;

final class ComposerPharReleaseClient implements ReleaseClientInterface
{
    /**
     * @var list<string>
     */
    public array $downloadedUrls = [];

    public function __construct(
        private readonly ?string $payload,
    ) {}

    #[Override]
    public function get(string $url): string
    {
        throw SelfUpdateFailedException::forFailedDownload($url);
    }

    #[Override]
    public function download(string $url, string $destination, ?Closure $onProgress = null): void
    {
        $this->downloadedUrls[] = $url;

        if (null === $this->payload) {
            throw SelfUpdateFailedException::forFailedDownload($url);
        }

        (new Filesystem())->dumpFile($destination, $this->payload);
    }
}
