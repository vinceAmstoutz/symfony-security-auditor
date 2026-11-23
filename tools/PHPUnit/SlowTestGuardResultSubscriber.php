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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\PHPUnit;

use Ergebnis\PHPUnit\SlowTestDetector\Collector\Collector;
use Override;
use PHPUnit\Event\Application\Finished;
use PHPUnit\Event\Application\FinishedSubscriber;

/**
 * Fails the run when the detector's collector holds a test over its maximum
 * duration, the guard's headroom-adjusted bar or its own `#[MaximumDuration]`:
 * the enforcing half of {@see SlowTestGuardExtension}.
 */
final readonly class SlowTestGuardResultSubscriber implements FinishedSubscriber
{
    public function __construct(
        private Collector $collector,
    ) {}

    #[Override]
    public function notify(Finished $event): void
    {
        $slowTestList = $this->collector->slowTestList();
        if ($slowTestList->isEmpty()) {
            return;
        }

        $slowTests = $slowTestList->sortByDurationDescending()->toArray();

        $lines = [];
        foreach ($slowTests as $slowTest) {
            $duration = $slowTest->duration();
            $seconds = $duration->seconds() + $duration->nanoseconds() / 1_000_000_000;
            $lines[] = \sprintf('  %.3fs  %s', $seconds, $slowTest->testDescription()->toString());
        }

        fwrite(\STDERR, \sprintf(
            '%s[slow-test-guard] %d test(s) exceeded their maximum duration:%s%s%s',
            \PHP_EOL,
            \count($lines),
            \PHP_EOL,
            implode(\PHP_EOL, $lines),
            \PHP_EOL,
        ));

        exit(1);
    }
}
