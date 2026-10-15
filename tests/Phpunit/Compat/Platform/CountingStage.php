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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

/**
 * An application's own pipeline stage, tagged `symfony_security_auditor.pipeline_stage`
 * as `docs/extending.md` describes: it validates every finding and writes
 * what the context held when it ran next to the audited project.
 */
final readonly class CountingStage implements StageInterface
{
    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $found = 0;
        foreach ($auditContext->vulnerabilities() as $vulnerability) {
            ++$found;
            $auditContext->replaceVulnerability($vulnerability->withReviewerValidation(true));
        }

        file_put_contents(\sprintf('%s/../custom-stage.json', $auditContext->projectPath()), json_encode([
            'found' => $found,
            'validated' => \count($auditContext->validatedVulnerabilities()),
            'projectFiles' => \count($auditContext->projectFiles()),
            'mappingFiles' => \count($auditContext->mappingFiles()),
            'totalFindingsMeta' => $auditContext->getMeta('audit.total_findings'),
        ]));
    }

    #[Override]
    public function name(): string
    {
        return 'custom_dedupe';
    }
}
