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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;

/**
 * The figures of a dry run and the footnote under them. A subscription,
 * which is not billed per call, shows tokens without a price.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class DryRunEstimate
{
    public function __construct(
        private bool $onSubscription,
    ) {}

    public function render(SymfonyStyle $symfonyStyle, AuditCost $auditCost): void
    {
        if ('' !== $auditCost->primaryModel()) {
            $symfonyStyle->listing($this->lines($auditCost));
        }

        $symfonyStyle->comment(DryRunFootnote::of(self::reviewerRatioPercent($auditCost), $this->onSubscription));
    }

    /**
     * @return list<string>
     */
    private function lines(AuditCost $auditCost): array
    {
        $lines = [
            \sprintf('Model : %s', OutputFormatter::escape($auditCost->primaryModel())),
            \sprintf('Tokens: %s in / %s out (total: %s)', number_format($auditCost->inputTokens()), number_format($auditCost->outputTokens()), number_format($auditCost->totalTokens())),
        ];

        if (!$this->onSubscription) {
            $lines[] = \sprintf('Cost  : $%s (estimate)', number_format($auditCost->estimatedCostUsd(), 4, '.', ''));
        }

        foreach ($auditCost->byRole() as $role => $entry) {
            $lines[] = $this->roleLine($role, $entry);
        }

        return $lines;
    }

    /**
     * @param array{model: string, input_tokens: int, output_tokens: int, estimated_cost_usd: float} $entry
     */
    private function roleLine(string $role, array $entry): string
    {
        $tokens = \sprintf('%s in / %s out', number_format($entry['input_tokens']), number_format($entry['output_tokens']));

        return $this->onSubscription
            ? \sprintf('  %-8s (%s): %s', $role, OutputFormatter::escape($entry['model']), $tokens)
            : \sprintf('  %-8s (%s): $%s — %s', $role, OutputFormatter::escape($entry['model']), number_format($entry['estimated_cost_usd'], 4, '.', ''), $tokens);
    }

    private static function reviewerRatioPercent(AuditCost $auditCost): ?int
    {
        $byRole = $auditCost->byRole();
        $attackerInputTokens = $byRole[AgentRole::Attacker->value]['input_tokens'] ?? 0;
        $reviewerInputTokens = $byRole[AgentRole::Reviewer->value]['input_tokens'] ?? null;

        if (null === $reviewerInputTokens || 0 === $attackerInputTokens) {
            return null;
        }

        return (int) round($reviewerInputTokens / $attackerInputTokens * 100);
    }
}
