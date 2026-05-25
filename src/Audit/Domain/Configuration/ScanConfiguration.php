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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration;

final readonly class ScanConfiguration
{
    /**
     * @param list<string> $includedPaths
     * @param list<string> $additionalScrubberPatterns
     */
    public function __construct(
        public array $includedPaths,
        public bool $respectGitignore,
        public int $maxFileSizeKb,
        public bool $secretScrubbingEnabled,
        public array $additionalScrubberPatterns,
    ) {}
}
