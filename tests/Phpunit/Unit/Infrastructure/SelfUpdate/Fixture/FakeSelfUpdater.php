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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdaterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateStatus;

final class FakeSelfUpdater implements SelfUpdaterInterface
{
    public int $calls = 0;

    public ?bool $lastCheckOnly = null;

    public function __construct(
        public string $latestVersion = '0.0.0',
        public bool $throws = false,
    ) {}

    /**
     * @throws SelfUpdateFailedException
     */
    #[Override]
    public function run(string $currentVersion, bool $checkOnly): SelfUpdateResult
    {
        ++$this->calls;
        $this->lastCheckOnly = $checkOnly;

        if ($this->throws) {
            throw SelfUpdateFailedException::forFailedDownload('https://example.test');
        }

        return new SelfUpdateResult(SelfUpdateStatus::UpdateAvailable, $currentVersion, $this->latestVersion);
    }
}
