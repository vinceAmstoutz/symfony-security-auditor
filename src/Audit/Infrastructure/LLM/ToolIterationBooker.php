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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Symfony\AI\Platform\Result\DeferredResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;

/**
 * Books the usage one answered round of a tool-using conversation reported:
 * on the rate-limit window first, then against the budget — checking it right
 * after, since that round may have spent it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ToolIterationBooker
{
    public function __construct(
        private string $model,
        private RateLimiterInterface $rateLimiter,
        private ?BudgetTracker $budgetTracker,
        private PlatformResultExtractor $platformResultExtractor,
    ) {}

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     */
    public function book(DeferredResult $deferredResult, TokenUsageSnapshot $tokenUsageSnapshot): void
    {
        $this->rateLimiter->record($tokenUsageSnapshot->inputTokens(), $tokenUsageSnapshot->outputTokens());

        if (!$this->budgetTracker instanceof BudgetTracker) {
            return;
        }

        $this->budgetTracker->recordCall(LLMResponse::of(
            '',
            $this->model,
            'tool_iteration',
            $tokenUsageSnapshot,
        )->withReportedModel($this->platformResultExtractor->extractReportedModel($deferredResult)));
        $this->budgetTracker->assertWithinBudget();
    }
}
