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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Mcp\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;

/**
 * Test fake — a run over one file the attacker left with the given status,
 * reporting the given already-validated findings, which remembers the baseline
 * fingerprints the run was handed.
 *
 * @internal scoped to the MCP audit tool integration tests
 */
final class SingleFileAuditPipeline implements PipelineInterface
{
    public const string FILE = 'src/Controller/HomeController.php';

    /** @var list<string> */
    public array $acceptedFingerprints = [];

    /** @var list<Vulnerability> */
    private readonly array $vulnerabilities;

    public function __construct(
        private readonly string $attackerStatus = 'analyzed',
        Vulnerability ...$vulnerabilities,
    ) {
        $this->vulnerabilities = array_values($vulnerabilities);
    }

    /**
     * @throws InvalidProjectFileException
     */
    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $this->acceptedFingerprints = $auditContext->acceptedFingerprints();
        $auditContext->setProjectFiles([ProjectFile::create(self::FILE, self::FILE, '<?php')]);
        $auditContext->recordCoverage('attacker', self::FILE, $this->attackerStatus);

        foreach ($this->vulnerabilities as $vulnerability) {
            $auditContext->addVulnerability($vulnerability);
        }
    }
}
