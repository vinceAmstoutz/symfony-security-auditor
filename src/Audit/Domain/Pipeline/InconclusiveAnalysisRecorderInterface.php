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
 * Opt-in companion of {@see CoverageRecorderInterface} for a recorder that
 * keeps which `analyzed` files the model judged on a partial look — it
 * reached its last tool round and found nothing — so the analyzers neither
 * cache that answer as safe nor read it as a verdict. The analyzers check for
 * it with `instanceof`, so a recorder without it keeps working.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface InconclusiveAnalysisRecorderInterface
{
    public function recordInconclusiveAnalysis(string $stage, string $filePath): void;
}
