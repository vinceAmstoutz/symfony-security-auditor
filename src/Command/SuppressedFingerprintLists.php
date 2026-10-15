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

/**
 * The findings a report left out because the baseline accepted them or their
 * type is muted, one entry per occurrence: under the fingerprint a report
 * lists the finding under, and, in the same order, under the baseline
 * fingerprint that left it out.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SuppressedFingerprintLists
{
    /**
     * @param list<string> $listed   the fingerprint a report lists each finding under
     * @param list<string> $baseline the baseline fingerprint that left each of them out
     */
    public function __construct(
        public array $listed,
        public array $baseline,
    ) {}
}
