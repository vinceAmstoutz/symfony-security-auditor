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
 * Optional extension of {@see LoadOrderAwareSecurityConfigParserInterface},
 * checked with `instanceof`: the files the application loads, those they
 * import and, for a run narrowed to a folder, the configuration of that
 * folder's application. Without it, each file goes through
 * {@see ProductionAwareSecurityConfigParserInterface::isLoadedInProduction()}
 * and {@see LoadOrderAwareSecurityConfigParserInterface::loadRank()}.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface ImportAwareSecurityConfigParserInterface extends LoadOrderAwareSecurityConfigParserInterface
{
    /**
     * @param list<ProjectFile> $files     the files the run maps
     * @param list<string>      $scanPaths the run's `--path` values, normalized; empty for the whole project
     */
    public function productionConfiguration(array $files, array $scanPaths): ProductionConfiguration;
}
