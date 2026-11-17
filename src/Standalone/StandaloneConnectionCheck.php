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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConnectionCheckInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConnectionProbe;

/**
 * Builds the audit's container from the saved configuration, as a run
 * would, and sends its LLM client the one short request of the probe.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneConnectionCheck implements ConnectionCheckInterface
{
    public function __construct(
        private StandaloneConfigLoader $standaloneConfigLoader,
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandaloneContainerFactory $standaloneContainerFactory = new StandaloneContainerFactory(),
        private ConnectionProbe $connectionProbe = new ConnectionProbe(),
    ) {}

    #[Override]
    public function failureReason(): ?string
    {
        try {
            $llmClient = $this->standaloneContainerFactory
                ->create($this->standaloneConfigLoader->load(), $this->xdgConfigPathResolver->cacheDir())
                ->get(LLMClientInterface::class);
        } catch (Throwable $throwable) {
            return $throwable->getMessage();
        }

        \assert($llmClient instanceof LLMClientInterface);

        return $this->connectionProbe->failureReason($llmClient);
    }
}
