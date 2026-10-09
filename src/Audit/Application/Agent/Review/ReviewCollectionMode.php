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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StructuredCollectionAwareReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * How the reviewer collects its verdicts, decided once from the configuration
 * and from what is wired: the investigation tools opt-in keeps the JSON path,
 * and so does a structured request the wiring cannot serve (no `record_review`
 * factory, or concurrency asked of a client that cannot batch tools). The
 * prompts follow the mode that runs, never the configured default.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReviewCollectionMode
{
    private function __construct(
        private ?ToolRegistryFactoryInterface $toolRegistryFactory,
        public bool $structured,
    ) {}

    public static function resolve(
        ReviewerModeConfiguration $reviewerModeConfiguration,
        ReviewerAgentCollaborators $reviewerAgentCollaborators,
        ?ToolRegistryFactoryInterface $toolRegistryFactory,
    ): self {
        $investigationToolFactory = $reviewerModeConfiguration->toolsEnabled ? $toolRegistryFactory : null;

        return new self($investigationToolFactory, !$investigationToolFactory instanceof ToolRegistryFactoryInterface && self::servesStructuredCollection($reviewerModeConfiguration, $reviewerAgentCollaborators));
    }

    public function usesTools(): bool
    {
        return $this->toolRegistryFactory instanceof ToolRegistryFactoryInterface;
    }

    /**
     * @param list<ProjectFile> $projectFiles
     *
     * @throws InvalidToolRegistryException
     */
    public function toolRegistry(array $projectFiles): ?ToolRegistry
    {
        return $this->toolRegistryFactory?->forProjectFiles($projectFiles);
    }

    public function promptBuilder(ReviewerPromptBuilderInterface $reviewerPromptBuilder): ReviewerPromptBuilderInterface
    {
        return $reviewerPromptBuilder instanceof StructuredCollectionAwareReviewerPromptBuilderInterface
            ? $reviewerPromptBuilder->withStructuredCollection($this->structured)
            : $reviewerPromptBuilder;
    }

    private static function servesStructuredCollection(ReviewerModeConfiguration $reviewerModeConfiguration, ReviewerAgentCollaborators $reviewerAgentCollaborators): bool
    {
        return $reviewerModeConfiguration->useStructuredCollection
            && $reviewerAgentCollaborators->recordReviewToolFactory instanceof RecordReviewToolFactoryInterface
            && ($reviewerModeConfiguration->batchSize > 1 || $reviewerModeConfiguration->maxConcurrent <= 1 || $reviewerAgentCollaborators->llmClient instanceof ToolBatchCapableLLMClientInterface);
    }
}
