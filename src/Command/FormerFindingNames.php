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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

/**
 * The former names an older baseline may hold a finding under: the path the
 * model echoed for it (`./src/A.php`, `src\A.php`, `/src/A.php`, an absolute
 * path inside the report's project) and the former types of its type, as
 * `Vulnerability::fingerprintCandidates()` lists them. Only the spellings the
 * baseline's entries name are tried.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class FormerFindingNames
{
    /**
     * @param array<string, array<string, string>> $spellingsByForm the files the entries name, under their comparable form
     */
    private function __construct(
        private ?string $projectPath,
        private array $spellingsByForm,
    ) {}

    /**
     * @param list<BaselineEntry> $baselineEntries
     */
    public static function in(LoadedReport $loadedReport, array $baselineEntries): self
    {
        $spellingsByForm = [];
        foreach ($baselineEntries as $baselineEntry) {
            $file = $baselineEntry->file();
            if (null !== $file) {
                $spellingsByForm[EchoedFilePath::comparable($file)][$file] = $file;
            }
        }

        return new self($loadedReport->projectPath, $spellingsByForm);
    }

    /**
     * Each fingerprint an entry holds `$diffFinding` under, with the file the
     * entry must name for it (null for any file). None for a report without a
     * project path, whose findings keep the paths the model echoed.
     *
     * @return list<array{string|null, string}>
     */
    public function of(DiffFinding $diffFinding): array
    {
        if (null === $this->projectPath) {
            return [];
        }

        $types = $this->typesOf($diffFinding);
        $names = [];
        foreach ([null, ...$this->spellingsOf($diffFinding->file, $this->projectPath)] as $entryFile) {
            foreach ($types as $type) {
                $names[] = [$entryFile, Vulnerability::fingerprintOf($type, $entryFile ?? $diffFinding->file, $diffFinding->title)];
            }
        }

        return $names;
    }

    /**
     * @return list<string>
     */
    private function spellingsOf(string $file, string $projectPath): array
    {
        $spellings = [];
        foreach (EchoedFilePath::projectFileForms($file, $projectPath) as $form) {
            foreach ($this->spellingsByForm[$form] ?? [] as $spelling) {
                $spellings[] = $spelling;
            }
        }

        return $spellings;
    }

    /**
     * @return list<string>
     */
    private function typesOf(DiffFinding $diffFinding): array
    {
        return [
            $diffFinding->type,
            ...array_map(
                static fn (VulnerabilityType $vulnerabilityType): string => $vulnerabilityType->value,
                VulnerabilityType::tryFrom($diffFinding->type)?->formerTypes() ?? [],
            ),
        ];
    }
}
