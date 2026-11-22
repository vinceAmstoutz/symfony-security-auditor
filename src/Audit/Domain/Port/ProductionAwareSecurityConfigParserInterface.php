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
 * Optional extension of {@see SecurityConfigParserInterface}, checked with
 * `instanceof`: tells which configuration files the application loads in
 * production. The access control and firewalls of any other file are not
 * read; without it, every configuration file is.
 */
interface ProductionAwareSecurityConfigParserInterface extends SecurityConfigParserInterface
{
    /**
     * @param string $relativePath the configuration file's path, relative to the project root
     */
    public function isLoadedInProduction(string $relativePath): bool;
}
