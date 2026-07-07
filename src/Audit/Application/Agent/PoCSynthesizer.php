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
 * Generates a concrete, copy-pasteable proof-of-concept (curl, console,
 * request body, …) for every accepted finding at or above the configured
 * severity floor (default HIGH). The original attacker `proof` is preserved;
 * the synthesized PoC is attached via `Vulnerability::withSynthesizedPoC()`.
 */
final readonly class PoCSynthesizer implements PoCSynthesizerInterface
{
    private const string NO_POC_SENTINEL = 'NO_POC:';

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
            if (!$this->qualifiesForSynthesis($vulnerability)) {
                $enriched[] = $vulnerability;
                ++$skipped;

                continue;
            }

            $poc = $this->synthesizeOne($vulnerability);

            if (null === $poc) {
                $enriched[] = $vulnerability;
                ++$skipped;

                continue;
            }

            $enriched[] = $vulnerability->withSynthesizedPoC($poc);
            ++$synthesized;
        }

        $this->logger->info('PoC synthesis complete', [
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
        $systemPrompt = $this->buildSystemPrompt();
        $userMessage = $this->buildUserMessage($vulnerability);

        try {
            $response = $this->llmClient->complete($systemPrompt, $userMessage);
            $content = u($response->content())->trim()->toString();

            return $this->isUsablePoC($content) ? $content : null;
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            $this->logger->error('PoC synthesis call failed; keeping original proof', [
                'vulnerability_id' => $vulnerability->id(),
                'error' => $exception->getMessage(),
            ]);

            return null;
        }
    }

    private function isUsablePoC(string $content): bool
    {
        return '' !== $content && !u($content)->startsWith(self::NO_POC_SENTINEL);
    }

    private function buildSystemPrompt(): string
    {
        return <<<'PROMPT'
            You are a senior offensive security engineer producing reproducible
            proof-of-concept artifacts for confirmed Symfony vulnerabilities.

            Given a validated finding, output ONE concrete reproduction artifact
            tailored to the vulnerability type:

            - Web routes: a single `curl` command (method, full URL, headers,
              minimal body) plus the expected response shape that demonstrates
              the impact.
            - Console / CLI: an exact `bin/console <command>` invocation with the
              specific argument that triggers the issue.
            - Messenger / async: a `bin/console messenger:consume <transport>`
              line plus the JSON payload that, once dispatched, hits the sink.
            - Twig SSTI / XSS: the literal payload string that triggers the
              behaviour, plus the route that renders it.
            - Cryptography / weak random: a one-liner showing the predictable
              output (e.g. `php -r 'echo mt_rand(0, 9999);'` enumeration).
            - Authorization / IDOR: two `curl` snippets — one as the rightful
              user (control), one as the attacker (showing the leak).

            Output ONLY the artifact — no prose intro, no closing commentary,
            no markdown fence around the whole thing. Use ```sh fences ONLY
            around shell commands and ```http or ```json ONLY around payload
            bodies. Keep it short and copy-pasteable.

            If the finding describes something that cannot be reproduced from
            outside the running app (e.g. internal race-condition with no
            triggerable entrypoint), respond with `NO_POC: <one-line reason>`.
            PROMPT;
    }

    private function buildUserMessage(Vulnerability $vulnerability): string
    {
        $data = $vulnerability->toArray();

        return \sprintf(
            <<<'MSG'
                ## Vulnerability to reproduce

                ID: %s
                Type: %s
                Severity: %s
                Title: %s
                File: %s (lines %d-%d)

                ### Vulnerable code
                ```
                %s
                ```

                ### Attack vector (from initial finding)
                %s

                ### Attacker's initial proof (may be vague)
                %s

                ### Remediation (for context — do NOT include in PoC)
                %s

                Produce the concrete PoC now.
                MSG,
            $data['id'],
            $data['type'],
            $data['severity'],
            $this->escapeFences($data['title']),
            $this->escapeFences($data['file']),
            $data['line_start'],
            $data['line_end'],
            $this->escapeFences($data['vulnerable_code']),
            $this->escapeFences($data['attack_vector']),
            $this->escapeFences($data['proof']),
            $this->escapeFences($data['remediation']),
        );
    }

    /**
     * LLM-echoed finding text is interpolated into this prompt's own
     * ```-delimited code-fence and `###`-prefixed section headers; an
     * unescaped run of backticks would let the finding forge a fake fence,
     * and an unescaped `#` would let it forge a fake section header (e.g. a
     * bogus `### SYSTEM OVERRIDE`) as unguarded top-level prompt text.
     */
    private function escapeFences(string $text): string
    {
        return str_replace(['`', '#'], ['\\`', '\\#'], $text);
    }
}
