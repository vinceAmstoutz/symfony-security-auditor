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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Bridge\ClaudeCode\ModelCatalog;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentModelCatalog;

final class CliAgentModelCatalogTest extends TestCase
{
    public function test_it_lists_the_models_its_bridge_lists(): void
    {
        $modelCatalog = new ModelCatalog();

        self::assertSame($modelCatalog->getModels(), (new CliAgentModelCatalog($modelCatalog, 'opus'))->getModels());
    }
}
