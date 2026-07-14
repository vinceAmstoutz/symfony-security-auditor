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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdateResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\SelfUpdaterInterface;

final class RecordingSelfUpdater implements SelfUpdaterInterface
{
    public ?string $currentVersion = null;

    public ?bool $checkOnly = null;

    public function __construct(private readonly SelfUpdateResult $selfUpdateResult) {}

    /**
     * @throws void
     */
    #[Override]
    public function run(string $currentVersion, bool $checkOnly): SelfUpdateResult
    {
        $this->currentVersion = $currentVersion;
        $this->checkOnly = $checkOnly;

        return $this->selfUpdateResult;
    }
}
