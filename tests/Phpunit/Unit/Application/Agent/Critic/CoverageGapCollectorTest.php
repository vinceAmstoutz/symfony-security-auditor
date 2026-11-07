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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Critic;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageGapCollector;

final class CoverageGapCollectorTest extends TestCase
{
    public function test_drain_returns_the_recorded_gaps_in_order(): void
    {
        $coverageGapCollector = new CoverageGapCollector();
        $coverageGapCollector->add(['hypothesis' => 'first']);
        $coverageGapCollector->add(['hypothesis' => 'second']);

        self::assertSame([['hypothesis' => 'first'], ['hypothesis' => 'second']], $coverageGapCollector->drain());
    }

    public function test_drain_empties_the_collector(): void
    {
        $coverageGapCollector = new CoverageGapCollector();
        $coverageGapCollector->add(['hypothesis' => 'first']);
        $coverageGapCollector->drain();

        self::assertSame([], $coverageGapCollector->drain());
    }
}
