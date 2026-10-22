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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * The files a finding's echoed path may name. `name()` names a finding by the
 * known file its path denotes — an absolute path, a leading slash, backslashes
 * or a leading `./` alike ({@see EchoedFilePath::comparable()}) — so one file
 * has one spelling in every id, fingerprint and code lookup. Paths are compared
 * byte for byte: one that names a known file as written keeps naming the first
 * such file, these files before the later ones, and a folded spelling resolves
 * only when it denotes one known file alone, so a look-alike name (a
 * backslash, another Unicode form) never takes the findings of the file it
 * resembles. The paths are indexed once, so naming takes a few lookups
 * whatever the number of files.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class KnownFiles
{
    /** @var array<string, string> the relative path of the first file each path names as written */
    private array $relativePathByPath;

    /** @var array<string, array<string, string>> the relative paths of the files under each comparable form of their paths */
    private array $relativePathsByForm;

    /**
     * @param list<ProjectFile> $files
     * @param ?self             $later the known files a path is looked up in after these
     */
    public function __construct(array $files = [], private ?self $later = null)
    {
        $relativePathByPath = [];
        $relativePathsByForm = [];
        foreach ($files as $file) {
            $relativePath = $file->relativePath();
            foreach ([$relativePath, $file->absolutePath()] as $path) {
                $relativePathByPath[$path] ??= $relativePath;
                $relativePathsByForm[EchoedFilePath::comparable($path)][$relativePath] = $relativePath;
            }
        }

        $this->relativePathByPath = $relativePathByPath;
        $this->relativePathsByForm = $relativePathsByForm;
    }

    public function name(string $path): string
    {
        return $this->namedAsWritten($path) ?? $this->namedByForm($path);
    }

    private function namedAsWritten(string $path): ?string
    {
        return $this->relativePathByPath[$path] ?? $this->later?->namedAsWritten($path);
    }

    private function namedByForm(string $path): string
    {
        $denoted = $this->denotedBy(EchoedFilePath::comparable($path));

        return 1 === \count($denoted) ? array_values($denoted)[0] : $path;
    }

    /**
     * @return array<string, string> the relative paths of the known files whose paths share the comparable form `$form`, each once
     */
    private function denotedBy(string $form): array
    {
        return ($this->relativePathsByForm[$form] ?? []) + ($this->later?->denotedBy($form) ?? []);
    }
}
