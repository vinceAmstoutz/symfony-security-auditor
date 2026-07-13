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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/** @internal not part of the BC promise — the enum *values* (`ingestion`, `mapping`, `audit`, `poc_synthesis`) are the stable identifiers returned by the bundled `StageInterface::name()` implementations and surface in the `stage` field of every `ProgressEvent` payload. Custom stages registered through the `symfony_security_auditor.pipeline_stage` tag are free to pick any other string; this enum covers only the bundled stages. */
enum BuiltInStageName: string
{
    case Ingestion = 'ingestion';
    case Mapping = 'mapping';
    case Audit = 'audit';
    case PoCSynthesis = 'poc_synthesis';
    case FixSynthesis = 'fix_synthesis';
}
