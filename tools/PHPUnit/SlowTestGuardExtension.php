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

use Ergebnis\PHPUnit\SlowTestDetector\Collector\DefaultCollector;
use Ergebnis\PHPUnit\SlowTestDetector\Duration;
use Ergebnis\PHPUnit\SlowTestDetector\Extension as SlowTestDetectorExtension;
use Ergebnis\PHPUnit\SlowTestDetector\MaximumDuration;
use Ergebnis\PHPUnit\SlowTestDetector\Subscriber\Test\FinishedSubscriber;
use Ergebnis\PHPUnit\SlowTestDetector\Subscriber\Test\PreparationStartedSubscriber;
use Ergebnis\PHPUnit\SlowTestDetector\TimeKeeper;
use Ergebnis\PHPUnit\SlowTestDetector\Version\Series;
use Override;
use PHPUnit\Runner\Extension\Extension;
use PHPUnit\Runner\Extension\Facade;
use PHPUnit\Runner\Extension\ParameterCollection;
use PHPUnit\Runner\Version as PHPUnitVersion;
use PHPUnit\TextUI\Configuration\Configuration;

/**
 * Turns the report-only `ergebnis/phpunit-slow-test-detector` into a CI gate:
 * it registers the detector's own measurement (the `Test\PreparationStarted`
 * and `Test\Finished` subscribers, which honour per-test
 * `#[Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration]` overrides)
 * to collect tests that exceed the threshold, reads that collector, and fails
 * the run when it is non-empty. The threshold is the single `maximum-duration`
 * declared on the `Ergebnis\PHPUnit\SlowTestDetector\Extension` bootstrap, so
 * the report and the gate never drift apart; per-test attributes still relax it
 * where a container-boot test is legitimately slower.
 */
final readonly class SlowTestGuardExtension implements Extension
{
    private const string MAXIMUM_DURATION_PARAMETER = 'maximum-duration';

    private const int FALLBACK_MAXIMUM_DURATION_MILLISECONDS = 500;

    #[Override]
    public function bootstrap(Configuration $configuration, Facade $facade, ParameterCollection $parameters): void
    {
        $maximumDuration = MaximumDuration::fromDuration(
            Duration::fromMilliseconds($this->sharedMaximumDurationMilliseconds($configuration)),
        );
        $timeKeeper = new TimeKeeper();
        $defaultCollector = new DefaultCollector();

        $facade->registerSubscribers(
            new PreparationStartedSubscriber($timeKeeper),
            new FinishedSubscriber($maximumDuration, $timeKeeper, $defaultCollector, Series::fromString(PHPUnitVersion::series())),
            new SlowTestGuardResultSubscriber($defaultCollector),
        );
    }

    private function sharedMaximumDurationMilliseconds(Configuration $configuration): int
    {
        foreach ($configuration->extensionBootstrappers() as $extensionBootstrapper) {
            if (SlowTestDetectorExtension::class !== $extensionBootstrapper['className']) {
                continue;
            }

            $parameters = $extensionBootstrapper['parameters'];
            if (\array_key_exists(self::MAXIMUM_DURATION_PARAMETER, $parameters)) {
                return (int) $parameters[self::MAXIMUM_DURATION_PARAMETER];
            }
        }

        return self::FALLBACK_MAXIMUM_DURATION_MILLISECONDS;
    }
}
