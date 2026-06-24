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
 * @phpstan-type RoleMap array{controllers: list<ProjectFile>, entities: list<ProjectFile>, voters: list<ProjectFile>, repositories: list<ProjectFile>, forms: list<ProjectFile>, services: list<ProjectFile>, templates: list<ProjectFile>}
 */
final readonly class ProjectFileInventory
{
    /**
     * @param RoleMap $byRole
     */
    private function __construct(private array $byRole) {}

    /**
     * @param list<ProjectFile> $files
     */
    public static function fromFiles(array $files): self
    {
        return new self([
            'controllers' => self::filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isController()),
            'entities' => self::filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isEntity()),
            'voters' => self::filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isVoter()),
            'repositories' => self::filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isRepository()),
            'forms' => self::filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isForm()),
            'services' => self::filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isService()),
            'templates' => self::filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isTemplate()),
        ]);
    }

    /**
     * @param array<string, list<ProjectFile>> $byRole
     */
    public static function fromGroups(array $byRole): self
    {
        return new self([
            'controllers' => $byRole['controllers'] ?? [],
            'entities' => $byRole['entities'] ?? [],
            'voters' => $byRole['voters'] ?? [],
            'repositories' => $byRole['repositories'] ?? [],
            'forms' => $byRole['forms'] ?? [],
            'services' => $byRole['services'] ?? [],
            'templates' => $byRole['templates'] ?? [],
        ]);
    }

    /** @return list<ProjectFile> */
    public function controllers(): array
    {
        return $this->byRole['controllers'];
    }

    /** @return list<ProjectFile> */
    public function entities(): array
    {
        return $this->byRole['entities'];
    }

    /** @return list<ProjectFile> */
    public function voters(): array
    {
        return $this->byRole['voters'];
    }

    /** @return list<ProjectFile> */
    public function repositories(): array
    {
        return $this->byRole['repositories'];
    }

    /** @return list<ProjectFile> */
    public function forms(): array
    {
        return $this->byRole['forms'];
    }

    /** @return list<ProjectFile> */
    public function services(): array
    {
        return $this->byRole['services'];
    }

    /** @return list<ProjectFile> */
    public function templates(): array
    {
        return $this->byRole['templates'];
    }

    public function totalFiles(): int
    {
        return \count($this->byRole['controllers'])
            + \count($this->byRole['entities'])
            + \count($this->byRole['voters'])
            + \count($this->byRole['repositories'])
            + \count($this->byRole['forms'])
            + \count($this->byRole['services'])
            + \count($this->byRole['templates']);
    }

    public function hasVoterForEntity(string $entityName): bool
    {
        foreach ($this->byRole['voters'] as $voter) {
            if (str_contains($voter->content(), $entityName)) {
                return true;
            }
        }

        return false;
    }

    /** @return list<ProjectFile> */
    public function controllersWithoutVoters(): array
    {
        return self::filter(
            $this->byRole['controllers'],
            static fn (ProjectFile $projectFile): bool => !$projectFile->hasSecurityAnnotations(),
        );
    }

    /**
     * @param list<ProjectFile>           $files
     * @param callable(ProjectFile): bool $predicate
     *
     * @return list<ProjectFile>
     */
    private static function filter(array $files, callable $predicate): array
    {
        return array_values(array_filter($files, $predicate));
    }
}
