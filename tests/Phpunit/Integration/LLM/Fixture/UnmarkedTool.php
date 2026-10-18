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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

final readonly class UnmarkedTool implements ToolInterface
{
    public function __construct(private ToolInterface $tool) {}

    #[Override]
    public function definition(): ToolDefinition
    {
        return $this->tool->definition();
    }

    #[Override]
    public function execute(array $arguments): string
    {
        return $this->tool->execute($arguments);
    }
}
