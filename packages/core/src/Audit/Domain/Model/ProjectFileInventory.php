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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Model;

/**
 * @phpstan-type RoleMap array{entrypoints: list<ProjectFile>, domainModels: list<ProjectFile>, authorizationRules: list<ProjectFile>, persistenceQueries: list<ProjectFile>, inputBindings: list<ProjectFile>, services: list<ProjectFile>, templates: list<ProjectFile>}
 */
final readonly class ProjectFileInventory
{
    /**
     * @param RoleMap $byRole
     */
    private function __construct(private array $byRole) {}

    /**
     * @var array<string, SurfaceArchetype>
     */
    private const array BUCKETED_ARCHETYPES = [
        'entrypoints' => SurfaceArchetype::HTTP_ENTRYPOINT,
        'domainModels' => SurfaceArchetype::DOMAIN_MODEL,
        'authorizationRules' => SurfaceArchetype::AUTHORIZATION_RULE,
        'persistenceQueries' => SurfaceArchetype::PERSISTENCE_QUERY,
        'inputBindings' => SurfaceArchetype::INPUT_BINDING,
        'templates' => SurfaceArchetype::TEMPLATE,
    ];

    /**
     * @param list<ProjectFile> $files
     */
    public static function fromFiles(array $files): self
    {
        return new self([
            'entrypoints' => self::withArchetype($files, SurfaceArchetype::HTTP_ENTRYPOINT),
            'domainModels' => self::withArchetype($files, SurfaceArchetype::DOMAIN_MODEL),
            'authorizationRules' => self::withArchetype($files, SurfaceArchetype::AUTHORIZATION_RULE),
            'persistenceQueries' => self::withArchetype($files, SurfaceArchetype::PERSISTENCE_QUERY),
            'inputBindings' => self::withArchetype($files, SurfaceArchetype::INPUT_BINDING),
            'services' => self::filter($files, self::isUnbucketedPhpFile(...)),
            'templates' => self::withArchetype($files, SurfaceArchetype::TEMPLATE),
        ]);
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<ProjectFile>
     */
    private static function withArchetype(array $files, SurfaceArchetype $surfaceArchetype): array
    {
        return self::filter(
            $files,
            static fn (ProjectFile $projectFile): bool => $surfaceArchetype === $projectFile->fileType()->archetype(),
        );
    }

    /**
     * The residual bucket for every `.php` file whose archetype has no bucket of
     * its own — authentication, async handlers, event hooks, serialization and
     * anything unrecognized. Deliberately independent of
     * {@see ProjectFile::isService()}, whose narrower contract would drop those
     * from `totalFiles()` and the project summary instead of counting them.
     */
    private static function isUnbucketedPhpFile(ProjectFile $projectFile): bool
    {
        return !\in_array($projectFile->fileType()->archetype(), self::BUCKETED_ARCHETYPES, true)
            && str_ends_with($projectFile->relativePath(), '.php');
    }

    /**
     * @param array<string, list<ProjectFile>> $byRole
     */
    public static function fromGroups(array $byRole): self
    {
        return new self([
            'entrypoints' => $byRole['entrypoints'] ?? [],
            'domainModels' => $byRole['domainModels'] ?? [],
            'authorizationRules' => $byRole['authorizationRules'] ?? [],
            'persistenceQueries' => $byRole['persistenceQueries'] ?? [],
            'inputBindings' => $byRole['inputBindings'] ?? [],
            'services' => $byRole['services'] ?? [],
            'templates' => $byRole['templates'] ?? [],
        ]);
    }

    /** @return list<ProjectFile> */
    public function entrypoints(): array
    {
        return $this->byRole['entrypoints'];
    }

    /** @return list<ProjectFile> */
    public function domainModels(): array
    {
        return $this->byRole['domainModels'];
    }

    /** @return list<ProjectFile> */
    public function authorizationRules(): array
    {
        return $this->byRole['authorizationRules'];
    }

    /** @return list<ProjectFile> */
    public function persistenceQueries(): array
    {
        return $this->byRole['persistenceQueries'];
    }

    /** @return list<ProjectFile> */
    public function inputBindings(): array
    {
        return $this->byRole['inputBindings'];
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
        return \count($this->byRole['entrypoints'])
            + \count($this->byRole['domainModels'])
            + \count($this->byRole['authorizationRules'])
            + \count($this->byRole['persistenceQueries'])
            + \count($this->byRole['inputBindings'])
            + \count($this->byRole['services'])
            + \count($this->byRole['templates']);
    }

    public function hasAuthorizationRuleForModel(string $modelName): bool
    {
        $pattern = \sprintf('/\b%s\b/', preg_quote($modelName, '/'));
        foreach ($this->byRole['authorizationRules'] as $authorizationRule) {
            if (1 === preg_match($pattern, $authorizationRule->content())) {
                return true;
            }
        }

        return false;
    }

    /** @return list<ProjectFile> */
    public function entrypointsWithoutAuthorizationRule(): array
    {
        return self::filter(
            $this->byRole['entrypoints'],
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
