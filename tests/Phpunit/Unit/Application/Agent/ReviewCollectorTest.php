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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Phpunit\Unit\Application\Agent;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewCollector;

final class ReviewCollectorTest extends TestCase
{
    public function test_drain_returns_added_payloads_in_insertion_order(): void
    {
        $reviewCollector = new ReviewCollector();
        $reviewCollector->add(['id' => 'VULN-1', 'accepted' => true]);
        $reviewCollector->add(['id' => 'VULN-2', 'accepted' => false]);

        self::assertSame(
            [
                ['id' => 'VULN-1', 'accepted' => true],
                ['id' => 'VULN-2', 'accepted' => false],
            ],
            $reviewCollector->drain(),
        );
    }

    public function test_drain_empties_the_collector(): void
    {
        $reviewCollector = new ReviewCollector();
        $reviewCollector->add(['id' => 'VULN-1', 'accepted' => true]);
        $reviewCollector->drain();

        self::assertSame([], $reviewCollector->drain());
    }

    public function test_drain_on_fresh_collector_returns_empty_list(): void
    {
        self::assertSame([], (new ReviewCollector())->drain());
    }
}
