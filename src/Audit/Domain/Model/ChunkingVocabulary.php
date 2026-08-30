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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * The file conventions a framework profile chunks by: which surfaces the
 * attacker should see first, the class-name suffix that marks an entrypoint as
 * naming a feature, and the template extensions that sit in front of `.php`.
 * An instance with no conventions is deliberately usable — it chunks by feature
 * without renaming or reordering anything — so a profile that supplies none is
 * neutral rather than silently borrowing another framework's.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkingVocabulary
{
    /**
     * @param list<ProjectFileType>                    $surfacePriority    the order the attacker sees surfaces in;
     *                                                                     anything absent is analyzed last
     * @param array<value-of<ProjectFileType>, string> $featureSuffixes    the class-name suffix each entrypoint type
     *                                                                     drops to yield its feature name
     * @param list<string>                             $templateExtensions
     */
    public function __construct(
        private array $surfacePriority = [],
        private array $featureSuffixes = [],
        private array $templateExtensions = [],
    ) {}

    public function priorityOf(ProjectFileType $projectFileType): int
    {
        $index = array_search($projectFileType, $this->surfacePriority, true);

        return false !== $index ? $index : \count($this->surfacePriority);
    }

    public function featureNameOf(ProjectFileType $projectFileType, string $baseName): string
    {
        $suffix = $this->featureSuffixes[$projectFileType->value] ?? null;

        if (null === $suffix) {
            return $baseName;
        }

        $suffixPosition = strrpos($baseName, $suffix);

        return false === $suffixPosition ? $baseName : substr($baseName, 0, $suffixPosition);
    }

    public function stripTemplateExtension(string $baseName): string
    {
        foreach ($this->templateExtensions as $templateExtension) {
            $stripped = $this->withoutSuffix($baseName, $templateExtension);

            if ($stripped !== $baseName) {
                return $stripped;
            }
        }

        return $baseName;
    }

    private function withoutSuffix(string $baseName, string $suffix): string
    {
        if (!str_ends_with($baseName, $suffix) || \strlen($baseName) === \strlen($suffix)) {
            return $baseName;
        }

        return substr($baseName, 0, -\strlen($suffix));
    }
}
