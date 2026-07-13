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

use Override;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;

use function Symfony\Component\String\u;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Generates a suggested fix — a minimal unified-diff patch against the
 * vulnerable file — for every accepted finding at or above the configured
 * severity floor (default HIGH). The attacker's `remediation` prose is
 * preserved; the patch is attached via `Vulnerability::withSuggestedFix()`.
 */
final readonly class FixSynthesizer implements FixSynthesizerInterface
{
    private const string NO_FIX_SENTINEL = 'NO_FIX:';

    public function __construct(
        private LLMClientInterface $llmClient,
        private LoggerInterface $logger,
        private VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
    ) {}

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[Override]
    public function synthesize(array $vulnerabilities): array
    {
        if ([] === $vulnerabilities) {
            return [];
        }

        $enriched = [];
        $synthesized = 0;
        $skipped = 0;

        foreach ($vulnerabilities as $vulnerability) {
            $fix = $this->qualifiesForSynthesis($vulnerability) ? $this->synthesizeOne($vulnerability) : null;

            if (null === $fix) {
                $enriched[] = $vulnerability;
                ++$skipped;

                continue;
            }

            $enriched[] = $vulnerability->withSuggestedFix($fix);
            ++$synthesized;
        }

        $this->logger->info('Fix synthesis complete', [
            'inputs' => \count($vulnerabilities),
            'synthesized' => $synthesized,
            'skipped' => $skipped,
        ]);

        return $enriched;
    }

    private function qualifiesForSynthesis(Vulnerability $vulnerability): bool
    {
        return $vulnerability->isReviewerValidated()
            && $vulnerability->severity()->score() >= $this->vulnerabilitySeverity->score();
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function synthesizeOne(Vulnerability $vulnerability): ?string
    {
        try {
            $response = $this->llmClient->complete($this->buildSystemPrompt(), $this->buildUserMessage($vulnerability));
            $content = u($response->content())->trim()->toString();

            return $this->isUsableFix($content) ? $content : null;
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            $this->logger->error('Fix synthesis call failed; keeping original remediation', [
                'vulnerability_id' => $vulnerability->id(),
                'error' => $exception->getMessage(),
            ]);

            return null;
        }
    }

    private function isUsableFix(string $content): bool
    {
        return '' !== $content && !u($content)->startsWith(self::NO_FIX_SENTINEL);
    }

    private function buildSystemPrompt(): string
    {
        return <<<'PROMPT'
            You are a senior Symfony security engineer producing minimal,
            reviewable fixes for confirmed vulnerabilities.

            Given a validated finding and the vulnerable code, output ONE
            unified-diff patch that remediates the issue and nothing else:

            - Start with `--- a/<file>` and `+++ b/<file>` header lines using
              the finding's file path.
            - Include one or more `@@` hunks with enough unchanged context lines
              to apply cleanly.
            - Change the fewest lines necessary. Do not reformat untouched code,
              rename symbols, or bundle unrelated hardening.
            - Prefer the framework-idiomatic fix (parameterized Doctrine query,
              `#[IsGranted]`, CSRF token, `hash_equals`, an escaping filter, a
              validator constraint) over a hand-rolled guard.

            Output ONLY the diff — no prose intro, no closing commentary. Wrap
            the whole patch in a single ```diff fenced block.

            If the finding cannot be fixed with a localized patch (needs a
            config change, a new class, a schema migration, or a
            cross-cutting redesign), respond with `NO_FIX: <one-line reason>`.
            PROMPT;
    }

    private function buildUserMessage(Vulnerability $vulnerability): string
    {
        $data = $vulnerability->toArray();

        return \sprintf(
            <<<'MSG'
                ## Vulnerability to fix

                Type: %s
                Severity: %s
                Title: %s
                File: %s (lines %d-%d)

                ### Vulnerable code
                ```
                %s
                ```

                ### Attack vector
                %s

                ### Suggested remediation (prose, from the finding)
                %s

                Produce the unified-diff patch now.
                MSG,
            $data['type'],
            $data['severity'],
            $this->stripEmbeddedNewline($this->escapeFences($data['title'])),
            $this->stripEmbeddedNewline($data['file']),
            $data['line_start'],
            $data['line_end'],
            $this->escapeFences($data['vulnerable_code']),
            $this->escapeFences($data['attack_vector']),
            $this->escapeFences($data['remediation']),
        );
    }

    /**
     * LLM-echoed finding text is interpolated into this prompt's own
     * ```-delimited code-fence and `###`-prefixed section headers; an
     * unescaped run of backticks would let the finding forge a fake fence,
     * and an unescaped `#` would let it forge a fake section header as
     * unguarded top-level prompt text.
     */
    private function escapeFences(string $text): string
    {
        return str_replace(['`', '#'], ['\\`', '\\#'], $text);
    }

    /**
     * `title` lands in the bare, single-line `Title: ...` slot with no
     * surrounding fence or heading to contain it. A raw newline here would
     * forge a fake standalone instruction paragraph as unguarded top-level
     * prompt text.
     */
    private function stripEmbeddedNewline(string $text): string
    {
        return str_replace("\n", ' ', $text);
    }
}
