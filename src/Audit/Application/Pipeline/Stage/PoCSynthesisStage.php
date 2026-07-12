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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage;

use Override;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\PoCSynthesizerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class PoCSynthesisStage implements StageInterface
{
    public function __construct(
        private PoCSynthesizerInterface $poCSynthesizer,
        private LoggerInterface $logger,
        private bool $enabled = false,
    ) {}

    #[Override]
    public function name(): string
    {
        return BuiltInStageName::PoCSynthesis->value;
    }

    #[Override]
    public function process(AuditContext $auditContext): void
    {
        if (!$this->enabled) {
            $this->logger->debug('PoC synthesis stage disabled, skipping');

            return;
        }

        $validated = $auditContext->validatedVulnerabilities();

        if ([] === $validated) {
            $this->logger->info('PoC synthesis: no validated findings to enrich');

            return;
        }

        $count = 0;
        foreach ($validated as $vulnerability) {
            [$enriched] = $this->poCSynthesizer->synthesize([$vulnerability]);
            if (null !== $enriched->synthesizedPoC()) {
                $auditContext->replaceVulnerability($enriched);
                ++$count;
            }
        }

        $auditContext->setMeta('audit.poc_synthesized', $count);

        $this->logger->info('PoC synthesis stage complete', [
            'enriched' => $count,
            'total_validated' => \count($validated),
        ]);
    }
}
