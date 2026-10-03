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
 * Opt-in extension of {@see SecurityConfigParserInterface} for parsers that
 * know which configuration files the application loads in production. A rule
 * in any other file — a test or development override, a file nothing imports
 * — protects no production route, so its access control and firewalls are
 * not read. Consumers check `instanceof ProductionAwareSecurityConfigParserInterface`
 * and read every configuration file when it is not implemented, so adding
 * this capability never breaks an existing parser.
 */
interface ProductionAwareSecurityConfigParserInterface extends SecurityConfigParserInterface
{
    /**
     * @param string $relativePath the configuration file's path, relative to the project root
     */
    public function isLoadedInProduction(string $relativePath): bool;
}
