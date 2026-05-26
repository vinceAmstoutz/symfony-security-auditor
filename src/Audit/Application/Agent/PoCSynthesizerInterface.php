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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/** @internal not part of the BC promise — see docs/versioning.md */
interface PoCSynthesizerInterface
{
    /**
     * Returns the validated findings with a `synthesizedPoC` populated for the
     * ones that warranted enrichment. Findings that did not (low severity,
     * synthesizer failure, etc.) are returned unchanged.
     *
     * @param list<Vulnerability> $vulnerabilities
     *
     * @return list<Vulnerability>
     */
    public function synthesize(array $vulnerabilities): array;
}
