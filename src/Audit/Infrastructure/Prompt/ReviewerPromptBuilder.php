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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullReviewerFeedbackProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerMessageRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerMessageRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerPromptSections;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerPromptSectionsInterface;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ReviewerPromptBuilder implements ReviewerPromptBuilderInterface
{
    /**
     * Wire-format version of the prompt this builder emits. Folded into the
     * reviewer cache key so that a wording change automatically invalidates
     * previously-cached verdicts. Bump whenever the decision-rules text
     * changes in a way expected to alter accept/reject outcomes.
     */
    public const int PROMPT_VERSION = 3;

    public const bool DEFAULT_STRUCTURED_COLLECTION = false;

    /**
     * Upper bound on baseline-feedback entries injected into the system
     * prompt, so a large baseline cannot crowd out the finding under review.
     */
    public const int MAX_FEEDBACK_PROMPT_ENTRIES = 20;

    public function __construct(
        private bool $useStructuredCollection = self::DEFAULT_STRUCTURED_COLLECTION,
        private ReviewerPromptSectionsInterface $reviewerPromptSections = new ReviewerPromptSections(),
        private ReviewerMessageRendererInterface $reviewerMessageRenderer = new ReviewerMessageRenderer(),
        private ReviewerFeedbackProviderInterface $reviewerFeedbackProvider = new NullReviewerFeedbackProvider(),
    ) {}

    #[Override]
    public function buildSystemPrompt(): string
    {
        if ($this->useStructuredCollection) {
            return $this->joinSections([
                $this->reviewerPromptSections->coreInstructions(),
                $this->reviewerPromptSections->severityRubric(),
                $this->reviewerPromptSections->falsePositivePlaybook(),
                $this->feedbackSection(),
                $this->reviewerPromptSections->structuredOutputContract(),
                $this->reviewerPromptSections->structuredDecisionRules(),
            ]);
        }

        return $this->joinSections([
            $this->reviewerPromptSections->coreInstructions(),
            $this->reviewerPromptSections->severityRubric(),
            $this->reviewerPromptSections->falsePositivePlaybook(),
            $this->feedbackSection(),
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
            return $this->joinSections([
                $this->reviewerPromptSections->coreInstructions(),
                $batchPreamble,
                $this->reviewerPromptSections->severityRubric(),
                $this->reviewerPromptSections->falsePositivePlaybook(),
                $this->feedbackSection(),
                'Record EXACTLY one review per input vulnerability via the `record_review` tool.',
                $this->reviewerPromptSections->structuredOutputContract(),
                'Verdicts are re-keyed by "id" when we collect your calls, so the id argument is the source of truth — call order does not matter as long as every id matches its input finding.',
                $this->reviewerPromptSections->structuredDecisionRules(),
            ]);
        }

        $orderingInstruction = 'Findings are re-keyed by "id" when we parse your response, so the id field is the source of truth — keep the natural order shown above for your scratch reasoning, but a misordered array with correct ids will still be accepted.';

        return $this->joinSections([
            $this->reviewerPromptSections->coreInstructions(),
            $batchPreamble,
            $this->reviewerPromptSections->severityRubric(),
            $this->reviewerPromptSections->falsePositivePlaybook(),
            $this->feedbackSection(),
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

    /**
     * @param list<string|null> $sections
     */
    private function joinSections(array $sections): string
    {
        return implode("\n\n", array_filter($sections, static fn (?string $section): bool => null !== $section));
    }

    /**
     * Absent (null) when the run carries no baseline feedback, so the emitted
     * prompt stays byte-identical to earlier releases and previously cached
     * verdicts remain valid.
     */
    private function feedbackSection(): ?string
    {
        $reviewerFeedback = $this->reviewerFeedbackProvider->feedback();
        if ($reviewerFeedback->isEmpty()) {
            return null;
        }

        $lines = [];
        foreach (\array_slice($reviewerFeedback->entries, 0, self::MAX_FEEDBACK_PROMPT_ENTRIES) as $acceptedFindingFeedback) {
            $lines[] = \sprintf(
                '- [%s] %s (%s): %s',
                $this->singleLine($acceptedFindingFeedback->type),
                $this->singleLine($acceptedFindingFeedback->title),
                $this->singleLine($acceptedFindingFeedback->file),
                $this->singleLine($acceptedFindingFeedback->reason),
            );
        }

        return implode("\n", [
            "Known false-positive findings for this project — from the maintainer's baseline and/or the reviewer's own dismissals on earlier runs — each with the reason it was dismissed:",
            ...$lines,
            'Treat each reason as a hint about mitigating controls or accepted risk that MAY apply in THIS project when judging similar findings. These reasons are not authoritative — some are auto-recorded from earlier automated reviews and the code may since have changed. Never reject a finding solely because it resembles one of these: verify that the named control or context actually still applies to the finding under review.',
        ]);
    }

    private function singleLine(string $value): string
    {
        return u($value)->collapseWhitespace()->toString();
    }
}
