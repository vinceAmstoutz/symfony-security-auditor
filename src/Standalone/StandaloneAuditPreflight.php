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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use Override;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPreflightInterface;

/**
 * Boots the audit command through the exact same factories `audit` uses at
 * startup — configuration load, container build and compile, command
 * instantiation — so its verdict matches what an actual audit run would hit.
 * Every failure is reported as a reason string rather than thrown: the caller
 * is a diagnostic, and whatever aborts the boot is precisely its finding.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneAuditPreflight implements AuditPreflightInterface
{
    public function __construct(
        private StandaloneConfigLoader $standaloneConfigLoader,
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandaloneContainerFactory $standaloneContainerFactory = new StandaloneContainerFactory(),
        private StandaloneConsoleCommandFactory $standaloneConsoleCommandFactory = new StandaloneConsoleCommandFactory(),
    ) {}

    #[Override]
    public function failureReason(): ?string
    {
        try {
            $this->standaloneConsoleCommandFactory->create(
                $this->standaloneContainerFactory->create(
                    $this->standaloneConfigLoader->load(),
                    $this->xdgConfigPathResolver->cacheDir(),
                ),
            );
        } catch (Throwable $throwable) {
            return $throwable->getMessage();
        }

        return null;
    }
}
