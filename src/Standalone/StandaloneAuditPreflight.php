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
 * Boots the audit command through the same factories `audit` uses at startup,
 * so its verdict matches a real run. Returns every failure as a reason string,
 * never throws.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
