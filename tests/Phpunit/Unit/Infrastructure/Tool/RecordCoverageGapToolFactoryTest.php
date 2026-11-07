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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Tool;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageGapCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordCoverageGapToolFactory;

final class RecordCoverageGapToolFactoryTest extends TestCase
{
    public function test_it_creates_a_record_coverage_gap_tool_that_feeds_the_given_collector(): void
    {
        $coverageGapCollector = new CoverageGapCollector();
        $arguments = ['files' => ['src/Controller/ExportController.php'], 'hypothesis' => 'The export skips the owner check.', 'attack_class' => 'broken_access_control'];

        $tool = (new RecordCoverageGapToolFactory())->create($coverageGapCollector);
        $tool->execute($arguments);

        self::assertSame(['record_coverage_gap', [$arguments]], [$tool->definition()->name, $coverageGapCollector->drain()]);
    }
}
