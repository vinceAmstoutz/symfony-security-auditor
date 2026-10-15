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
 * The configuration files the production application loads: those a parser
 * read, in the order the application loads them, the project's apart from
 * those of each monorepo application the run is narrowed to, and those it
 * could not read, each with the reason.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProductionConfiguration
{
    /**
     * @param list<ProjectFile>                $projectFiles
     * @param array<string, list<ProjectFile>> $applicationFiles the files of each application, by the application's folder, ending with a `/`
     * @param array<string, string>            $unreadableFiles  the reason each file could not be read, by relative path
     */
    public function __construct(
        public array $projectFiles,
        public array $applicationFiles = [],
        public array $unreadableFiles = [],
    ) {}
}
