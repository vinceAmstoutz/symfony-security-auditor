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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EchoedFilePath;

/**
 * What a JSON audit report tells a comparison: its findings, the files it
 * could not fully analyze, and — when it carries a coverage ledger — the files
 * its attacker analyzed or served from its cache. Only in those can the
 * absence of a finding prove anything.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LoadedReport
{
    /** @var array<string, int> */
    private array $unanalyzed;

    /** @var array<string, int>|null */
    private ?array $analyzed;

    /**
     * @param list<DiffFinding> $findings
     * @param list<string>      $unanalyzedFiles
     * @param list<string>|null $analyzedFiles   null for a report written before the coverage ledger existed
     */
    public function __construct(
        public array $findings,
        public array $unanalyzedFiles = [],
        public ?array $analyzedFiles = null,
    ) {
        $this->unanalyzed = array_flip(array_map(EchoedFilePath::normalize(...), $unanalyzedFiles));
        $this->analyzed = null === $analyzedFiles ? null : array_flip(array_map(EchoedFilePath::normalize(...), $analyzedFiles));
    }

    /**
     * Whether this report can vouch that a finding absent from it is gone from
     * `$file`: no stage of its run left the file unfinished, and its ledger says
     * the attacker analyzed the file or served it from its cache — a file the
     * lean pre-scan skipped, or one outside a `--since` or `--path` scope, was
     * never looked at. A report written before the ledger existed vouches for
     * every file it does not name as unanalyzed, as it always did. A finding
     * holds the path the attacker echoed, and so do the reviewer's entries in
     * the ledger, so a leading `./` is dropped on both sides before they are
     * compared.
     */
    public function vouchesForAbsenceIn(string $file): bool
    {
        $normalized = EchoedFilePath::normalize($file);

        return !\array_key_exists($normalized, $this->unanalyzed)
            && (null === $this->analyzed || \array_key_exists($normalized, $this->analyzed));
    }
}
