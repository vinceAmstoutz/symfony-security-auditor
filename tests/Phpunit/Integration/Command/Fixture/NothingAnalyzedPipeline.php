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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;

/**
 * Test fake — a run that reached its end with its only file never analyzed and
 * nothing found, the way a provider outage leaves every call failed.
 *
 * @internal scoped to AuditCommand incomplete-run integration tests
 */
final readonly class NothingAnalyzedPipeline implements PipelineInterface
{
    /**
     * @throws InvalidProjectFileException
     */
    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $auditContext->setProjectFiles([ProjectFile::create('src/Failed.php', 'src/Failed.php', '<?php')]);
        $auditContext->recordCoverage('attacker', 'src/Failed.php', 'errored');
    }
}
