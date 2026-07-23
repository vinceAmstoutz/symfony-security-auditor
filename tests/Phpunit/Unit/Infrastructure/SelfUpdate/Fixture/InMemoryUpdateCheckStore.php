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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\UpdateCheckState;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\UpdateCheckStoreInterface;

final class InMemoryUpdateCheckStore implements UpdateCheckStoreInterface
{
    public function __construct(
        private ?UpdateCheckState $updateCheckState = null,
    ) {}

    #[Override]
    public function read(): ?UpdateCheckState
    {
        return $this->updateCheckState;
    }

    #[Override]
    public function write(UpdateCheckState $updateCheckState): void
    {
        $this->updateCheckState = $updateCheckState;
    }
}
