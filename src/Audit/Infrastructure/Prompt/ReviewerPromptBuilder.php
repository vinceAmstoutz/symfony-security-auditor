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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerMessageRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerMessageRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerPromptSections;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerPromptSectionsInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ReviewerPromptBuilder implements ReviewerPromptBuilderInterface
{
    public const int PROMPT_VERSION = 1;

    public const bool DEFAULT_STRUCTURED_COLLECTION = false;

    public function __construct(
        private bool $useStructuredCollection = self::DEFAULT_STRUCTURED_COLLECTION,
        private ReviewerPromptSectionsInterface $reviewerPromptSections = new ReviewerPromptSections(),
        private ReviewerMessageRendererInterface $reviewerMessageRenderer = new ReviewerMessageRenderer(),
    ) {}

    #[Override]
    public function buildSystemPrompt(): string
    {
        if ($this->useStructuredCollection) {
            return implode("\n\n", [
                $this->reviewerPromptSections->coreInstructions(),
                $this->reviewerPromptSections->severityRubric(),
                $this->reviewerPromptSections->falsePositivePlaybook(),
                $this->reviewerPromptSections->structuredOutputContract(),
                $this->reviewerPromptSections->structuredDecisionRules(),
            ]);
        }

        return implode("\n\n", [
            $this->reviewerPromptSections->coreInstructions(),
            $this->reviewerPromptSections->severityRubric(),
            $this->reviewerPromptSections->falsePositivePlaybook(),
            'Your output must be a JSON array, one entry per vulnerability reviewed.',
            $this->reviewerPromptSections->jsonSchemaDescription(),
            $this->reviewerPromptSections->decisionRules(),
            $this->reviewerPromptSections->toolUsageDiscipline(),
        ]);
    }

    #[Override]
    public function buildBatchSystemPrompt(): string
    {
        $batchPreamble = 'You will receive SEVERAL vulnerability reports in a single batch and must validate each one.';

        if ($this->useStructuredCollection) {
            return implode("\n\n", [
                $this->reviewerPromptSections->coreInstructions(),
                $batchPreamble,
                $this->reviewerPromptSections->severityRubric(),
                $this->reviewerPromptSections->falsePositivePlaybook(),
                'Record EXACTLY one review per input vulnerability via the `record_review` tool.',
                $this->reviewerPromptSections->structuredOutputContract(),
                'Verdicts are re-keyed by "id" when we collect your calls, so the id argument is the source of truth — call order does not matter as long as every id matches its input finding.',
                $this->reviewerPromptSections->structuredDecisionRules(),
            ]);
        }

        $orderingInstruction = 'Findings are re-keyed by "id" when we parse your response, so the id field is the source of truth — keep the natural order shown above for your scratch reasoning, but a misordered array with correct ids will still be accepted.';

        return implode("\n\n", [
            $this->reviewerPromptSections->coreInstructions(),
            $batchPreamble,
            $this->reviewerPromptSections->severityRubric(),
            $this->reviewerPromptSections->falsePositivePlaybook(),
            'Your output MUST be a JSON array with EXACTLY one entry per input vulnerability.',
            $this->reviewerPromptSections->jsonSchemaDescription(),
            $orderingInstruction,
            $this->reviewerPromptSections->decisionRules(),
            $this->reviewerPromptSections->toolUsageDiscipline(),
        ]);
    }

    /**
     * @param list<Vulnerability>   $vulnerabilities
     * @param array<string, string> $codeContexts
     */
    #[Override]
    public function buildBatchUserMessage(array $vulnerabilities, array $codeContexts): string
    {
        return $this->reviewerMessageRenderer->renderBatch($vulnerabilities, $codeContexts, $this->useStructuredCollection);
    }

    #[Override]
    public function buildUserMessage(Vulnerability $vulnerability, string $codeContext): string
    {
        return $this->reviewerMessageRenderer->renderSingle($vulnerability, $codeContext, $this->useStructuredCollection);
    }
}
