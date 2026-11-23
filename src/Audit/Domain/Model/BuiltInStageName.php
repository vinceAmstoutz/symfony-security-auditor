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

/** @internal not part of the BC promise; its values are the stable names of the bundled stages, in the `stage` field of every progress event. */
enum BuiltInStageName: string
{
    case Ingestion = 'ingestion';
    case Mapping = 'mapping';
    case ProjectProfile = 'project_profile';
    case DependencyExpansion = 'dependency_expansion';
    case Audit = 'audit';
    case PoCSynthesis = 'poc_synthesis';
    case FixSynthesis = 'fix_synthesis';
}
