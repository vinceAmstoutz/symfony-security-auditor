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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline;

/**
 * Optional companion of {@see CoverageRecorderInterface}, checked with
 * `instanceof`: keeps which `analyzed` files the model answered at its last
 * tool round with no finding, an answer neither cached nor read as a verdict.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface InconclusiveAnalysisRecorderInterface
{
    public function recordInconclusiveAnalysis(string $stage, string $filePath): void;
}
