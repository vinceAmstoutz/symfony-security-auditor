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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EchoedFilePath;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BaselineFilePathsInterface;

/**
 * Carries the paths of the run's baseline entries and the audited project,
 * set by `audit:run` and the MCP `audit` tool before the run, to the
 * findings the run hydrates: a path names a project file when it denotes it
 * as `audit:baseline` reads it ({@see FormerFindingNames}). The paths are
 * indexed once, under the form the spellings of one file share, so naming a
 * finding's file takes two lookups whatever the size of the baseline.
 *
 * Mutable by design — non-readonly because the baseline is set after
 * construction. See .claude/rules/php-classes.md for the opt-out policy.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class BaselineFilePathsHolder implements BaselineFilePathsInterface
{
    private string $projectPath = '';

    /** @var array<string, array<int, string>> each path under its comparable form, keyed by its position in the baseline */
    private array $filePathsByForm = [];

    /**
     * @param iterable<int, string> $filePaths
     */
    public function set(string $projectPath, iterable $filePaths): void
    {
        $filePathsByForm = [];
        foreach ([...$filePaths] as $position => $filePath) {
            $filePathsByForm[EchoedFilePath::comparable($filePath)][$position] = $filePath;
        }

        $this->projectPath = $projectPath;
        $this->filePathsByForm = $filePathsByForm;
    }

    #[Override]
    public function naming(string $filePath): array
    {
        [$relativeForm, $absoluteForm] = EchoedFilePath::projectFileForms($filePath, $this->projectPath);
        $naming = ($this->filePathsByForm[$relativeForm] ?? []) + ($this->filePathsByForm[$absoluteForm] ?? []);
        ksort($naming);

        return array_values($naming);
    }
}
