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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool;

interface ToolInterface
{
    public function definition(): ToolDefinition;

    /**
     * @param array<string, mixed> $arguments
     */
    public function execute(array $arguments): string;
}
