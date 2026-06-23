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

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;

/**
 * The injected ports the reviewer agent builds its review strategies from.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReviewerAgentCollaborators
{
    public function __construct(
        public LLMClientInterface $llmClient,
        public ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        public LoggerInterface $logger,
        public ?RecordReviewToolFactoryInterface $recordReviewToolFactory = null,
        public ?ReviewerCacheInterface $reviewerCache = null,
        public ProgressReporterInterface $progressReporter = new NullProgressReporter(),
    ) {}
}
