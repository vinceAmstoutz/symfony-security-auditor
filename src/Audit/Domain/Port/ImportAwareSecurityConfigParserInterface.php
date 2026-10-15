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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProductionConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Opt-in extension of {@see LoadOrderAwareSecurityConfigParserInterface} for
 * parsers that know how the application assembles its configuration: the
 * files it loads, the files those import, and, for a run narrowed to a
 * folder, the configuration of the application that folder belongs to.
 * `MappingStage` checks `instanceof ImportAwareSecurityConfigParserInterface`
 * and otherwise asks {@see ProductionAwareSecurityConfigParserInterface::isLoadedInProduction()}
 * and {@see LoadOrderAwareSecurityConfigParserInterface::loadRank()} file by file.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ImportAwareSecurityConfigParserInterface extends LoadOrderAwareSecurityConfigParserInterface
{
    /**
     * @param list<ProjectFile> $files     the files the run maps
     * @param list<string>      $scanPaths the run's `--path` values, normalized; empty for the whole project
     */
    public function productionConfiguration(array $files, array $scanPaths): ProductionConfiguration;
}
