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

/**
 * Optional extension of {@see ProductionAwareSecurityConfigParserInterface},
 * checked with `instanceof`: the order the application loads its
 * configuration files in, which decides the first access control rule that
 * matches. Without it, files keep the order the scan listed them in.
 */
interface LoadOrderAwareSecurityConfigParserInterface extends ProductionAwareSecurityConfigParserInterface
{
    /**
     * Files of a lower rank load first; files of the same rank load in
     * relative-path order.
     *
     * @param string $relativePath the configuration file's path, relative to the project root
     */
    public function loadRank(string $relativePath): int;
}
