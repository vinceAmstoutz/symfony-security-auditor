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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;

/**
 * Test fake — bypasses the attacker/reviewer loop entirely and hands the
 * command a single, already-validated finding, so tests can exercise
 * baseline/report wiring without depending on the dual-agent loop's own
 * baseline-skip behavior. It records the finding's own file as scanned, since it
 * stands in for a pipeline whose ingestion stage ran — a report that discovered
 * no file at all carries no verdict and fails the exit-code gate.
 *
 * @internal scoped to AuditCommand baseline/SARIF integration tests
 */
final readonly class FixedFindingPipeline implements PipelineInterface
{
    public function __construct(
        private Vulnerability $vulnerability,
    ) {}

    /**
     * @throws InvalidProjectFileException
     */
    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $auditContext->setProjectFiles([
            ProjectFile::create($this->vulnerability->filePath(), $this->vulnerability->filePath(), '<?php'),
        ]);
        $auditContext->addVulnerability($this->vulnerability);
    }
}
