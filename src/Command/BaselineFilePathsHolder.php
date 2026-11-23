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
 * The paths the run's baseline names files by, set by `audit:run` and the MCP
 * `audit` tool before the run. `naming()` returns, in baseline order, the
 * paths that denote the given project file as `audit:baseline` reads them
 * ({@see FormerFindingNames}).
 *
 * Not readonly: the paths are set after construction. A late-bound holder
 * per .claude/rules/php-classes.md.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
