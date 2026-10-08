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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;

/**
 * Puts back, verbatim, the statement of every line the static pre-scanner
 * flagged: the line itself and, when it leaves a call open, the lines up to
 * the closing parenthesis — the arguments are what carry the vulnerability.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RiskMarkerLineRestorer
{
    public function __construct(
        private MultiLineCallExtent $multiLineCallExtent = new MultiLineCallExtent(),
    ) {}

    /**
     * @param list<RiskMarker> $markers
     */
    public function restore(ProjectFile $projectFile, string $slicedContent, array $markers): string
    {
        $originalLines = explode("\n", $projectFile->content());
        $slicedLines = explode("\n", $slicedContent);

        foreach ($markers as $marker) {
            foreach ($this->multiLineCallExtent->lineIndexes($originalLines, $marker->line() - 1) as $index) {
                if (\array_key_exists($index, $slicedLines)) {
                    $slicedLines[$index] = $originalLines[$index];
                }
            }
        }

        return implode("\n", $slicedLines);
    }
}
