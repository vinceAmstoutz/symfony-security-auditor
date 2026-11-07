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
 * Reads, from where a project's files sit and what they are, the
 * architecture styles it is laid out in.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProjectLayoutDetector
{
    private const string DOMAIN_LAYER = '/Domain/';

    private const array LAYERS = [self::DOMAIN_LAYER, '/Application/', '/Infrastructure/'];

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<ArchitectureStyle>
     */
    public static function stylesOf(array $files): array
    {
        $detected = [
            ArchitectureStyle::CQRS->value => self::anyFile($files, self::isCqrsHandler(...)),
            ArchitectureStyle::ACTION_DOMAIN_RESPONDER->value => self::anyFile($files, self::isSingleAction(...)),
            ArchitectureStyle::LAYERED->value => self::isLayered($files),
            ArchitectureStyle::BOUNDED_CONTEXTS->value => \count(self::boundedContextsOf($files)) > 1,
        ];

        return array_values(array_filter(
            ArchitectureStyle::cases(),
            static fn (ArchitectureStyle $architectureStyle): bool => $detected[$architectureStyle->value],
        ));
    }

    /**
     * The modules a project splits its domain into: the folder that holds
     * each `Domain/` layer.
     *
     * @param list<ProjectFile> $files
     *
     * @return list<string>
     */
    public static function boundedContextsOf(array $files): array
    {
        $contexts = [];
        foreach ($files as $file) {
            $domainAt = strpos($file->relativePath(), self::DOMAIN_LAYER);
            $module = false === $domainAt ? '' : substr($file->relativePath(), 0, $domainAt);
            if (str_contains($module, '/')) {
                $context = basename($module);
                $contexts[$context] = $context;
            }
        }

        return array_values($contexts);
    }

    /**
     * @param list<ProjectFile>           $files
     * @param callable(ProjectFile): bool $predicate
     */
    private static function anyFile(array $files, callable $predicate): bool
    {
        foreach ($files as $file) {
            if ($predicate($file)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<ProjectFile> $files
     */
    private static function isLayered(array $files): bool
    {
        foreach (self::LAYERS as $layer) {
            if (!self::anyFile($files, static fn (ProjectFile $projectFile): bool => str_contains($projectFile->relativePath(), $layer))) {
                return false;
            }
        }

        return true;
    }

    private static function isSingleAction(ProjectFile $projectFile): bool
    {
        return ProjectFileType::CONTROLLER === $projectFile->fileType()
            && 1 === preg_match('#/Actions?/[^/]+Action\.php$#', $projectFile->relativePath());
    }

    private static function isCqrsHandler(ProjectFile $projectFile): bool
    {
        return ProjectFileType::USE_CASE === $projectFile->fileType()
            || (ProjectFileType::MESSENGER_HANDLER === $projectFile->fileType() && 1 === preg_match('/(?:Command|Query)Handler\.php$/', $projectFile->relativePath()));
    }
}
