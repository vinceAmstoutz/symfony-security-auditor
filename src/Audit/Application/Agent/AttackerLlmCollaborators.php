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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;

/**
 * The LLM/finding seam the attacker agent turns chunk responses into findings with.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AttackerLlmCollaborators
{
    public function __construct(
        public LLMClientInterface $llmClient,
        public AttackerPromptBuilderInterface $attackerPromptBuilder,
        public VulnerabilityFactory $vulnerabilityFactory,
        public ?CodeSlicerInterface $codeSlicer = null,
        public ?RecordVulnerabilityToolFactoryInterface $recordVulnerabilityToolFactory = null,
    ) {}
}
