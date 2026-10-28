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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture;

use Closure;
use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ReleaseChannel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdaterInterface;

final class RecordingSelfUpdater implements SelfUpdaterInterface
{
    public ?string $currentVersion = null;

    public ?bool $checkOnly = null;

    public ?ReleaseChannel $releaseChannel = null;

    /**
     * @param list<int> $downloadProgress the byte counts handed to the progress callback, in order
     */
    public function __construct(
        private readonly SelfUpdateResult $selfUpdateResult,
        private readonly array $downloadProgress = [],
    ) {}

    /**
     * @throws void
     */
    #[Override]
    public function run(string $currentVersion, bool $checkOnly, ReleaseChannel $releaseChannel = ReleaseChannel::Stable, ?Closure $onDownloadProgress = null): SelfUpdateResult
    {
        $this->currentVersion = $currentVersion;
        $this->checkOnly = $checkOnly;
        $this->releaseChannel = $releaseChannel;

        foreach ($this->downloadProgress as $bytes) {
            $onDownloadProgress?->__invoke($bytes);
        }

        return $this->selfUpdateResult;
    }
}
