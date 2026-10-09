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
 * Opt-in extension of {@see ProductionAwareSecurityConfigParserInterface} for
 * parsers that know the order in which the application loads those files. An
 * application applies the first access control rule that matches a request,
 * and the rules come in load order, so a file loaded later never shadows a
 * rule of a file loaded earlier. Consumers check
 * `instanceof LoadOrderAwareSecurityConfigParserInterface` and keep the order
 * the scan listed the files in when it is not implemented, so adding this
 * capability never breaks an existing parser.
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
