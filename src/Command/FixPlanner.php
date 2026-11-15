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

use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\FilePatch;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\PatchApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\UnifiedDiff;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InvalidProjectPathException;

/**
 * Works out, fix by fix, what the suggested fixes of a report do to the
 * project: each fix applies to the files as the fixes before it left them, and
 * applies whole or not at all. A fix is refused when it is not a patch, when
 * it changes something other than a regular file inside the project — a path
 * through a symlink included — or when the code it was written for changed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FixPlanner
{
    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
        private PatchApplier $patchApplier = new PatchApplier(),
    ) {}

    /**
     * @param list<SuggestedFix> $suggestedFixes
     *
     * @throws InvalidProjectPathException
     */
    public function plan(array $suggestedFixes, string $projectPath): FixPlan
    {
        $realProjectPath = realpath($projectPath);
        if (false === $realProjectPath || !is_dir($realProjectPath)) {
            throw InvalidProjectPathException::forMissingDirectory($projectPath);
        }

        $projectRoot = Path::canonicalize($realProjectPath);
        $outcomes = [];
        $contents = [];
        foreach ($suggestedFixes as $suggestedFix) {
            $changed = $this->changedContents($suggestedFix, $projectRoot, $contents);
            $outcomes[] = new FixOutcome($suggestedFix, \is_string($changed) ? $changed : null);
            $contents = \is_array($changed) ? [...$contents, ...$changed] : $contents;
        }

        return new FixPlan($outcomes, $contents);
    }

    /**
     * @param array<string, string> $contents
     *
     * @return array<string, string>|string the files the fix changes, or why it does not apply
     */
    private function changedContents(SuggestedFix $suggestedFix, string $projectRoot, array $contents): array|string
    {
        $unifiedDiff = UnifiedDiff::parse($suggestedFix->patch);
        if (!$unifiedDiff instanceof UnifiedDiff) {
            return 'the suggested fix is not a patch the auditor can read';
        }

        $changed = [];
        foreach ($unifiedDiff->filePatches as $filePatch) {
            $target = Path::join($projectRoot, $filePatch->path);
            $patched = $this->patched($filePatch, $target, $changed[$target] ?? $contents[$target] ?? null);
            if (null === $patched) {
                return \sprintf('%s is not a file inside the project, or its code changed since the audit', $filePatch->path);
            }

            $changed[$target] = $patched;
        }

        return $changed;
    }

    private function patched(FilePatch $filePatch, string $target, ?string $content): ?string
    {
        if (null === $content && !$this->isRegularFileInside($target)) {
            return null;
        }

        try {
            return $this->patchApplier->apply($content ?? $this->filesystem->readFile($target), $filePatch);
        } catch (IOException) {
            return null;
        }
    }

    private function isRegularFileInside(string $target): bool
    {
        $realPath = realpath($target);

        return false !== $realPath && is_file($realPath) && Path::canonicalize($realPath) === $target;
    }
}
