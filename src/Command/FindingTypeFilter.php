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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class FindingTypeFilter implements FindingTypeFilterInterface
{
    /** @var list<VulnerabilityType> */
    private array $includedTypes;

    /** @var list<VulnerabilityType> */
    private array $excludedTypes;

    /**
     * @param list<string> $includedTypeValues
     * @param list<string> $excludedTypeValues
     */
    public function __construct(array $includedTypeValues = [], array $excludedTypeValues = [])
    {
        $this->includedTypes = array_map(VulnerabilityType::from(...), $includedTypeValues);
        $this->excludedTypes = array_map(VulnerabilityType::from(...), $excludedTypeValues);
    }

    public function apply(AuditReport $auditReport): AuditReport
    {
        return $auditReport->filteredByTypes($this->includedTypes, $this->excludedTypes);
    }
}
