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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer;

/**
 * Supplies the fixed text sections the reviewer system prompt is assembled from.
 * Kept out of the builder so the builder is pure composition, not a text dump.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ReviewerPromptSectionsInterface
{
    public function coreInstructions(): string;

    public function severityRubric(): string;

    public function falsePositivePlaybook(): string;

    public function jsonSchemaDescription(): string;

    public function decisionRules(): string;

    public function toolUsageDiscipline(): string;

    public function structuredOutputContract(): string;

    public function structuredDecisionRules(): string;
}
