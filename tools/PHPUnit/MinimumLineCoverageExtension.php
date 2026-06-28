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

use Override;
use PHPUnit\Runner\Extension\Extension;
use PHPUnit\Runner\Extension\Facade;
use PHPUnit\Runner\Extension\ParameterCollection;
use PHPUnit\TextUI\Configuration\Configuration;

/**
 * Fails the run when line coverage drops below the configured `min-coverage`
 * percentage. Reads the Clover report PHPUnit produces, so it only enforces
 * when a coverage run is requested (e.g. --coverage-clover).
 */
final readonly class MinimumLineCoverageExtension implements Extension
{
    private const float DEFAULT_MINIMUM = 100.0;

    #[Override]
    public function bootstrap(Configuration $configuration, Facade $facade, ParameterCollection $parameters): void
    {
        $minimumCoverage = $parameters->has('min-coverage')
            ? (float) $parameters->get('min-coverage')
            : self::DEFAULT_MINIMUM;

        $cloverPath = $configuration->hasCoverageClover() ? $configuration->coverageClover() : null;

        $facade->registerSubscriber(new MinimumLineCoverageSubscriber($cloverPath, $minimumCoverage));
    }
}
