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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * An application's own `LLMClientInterface`, aliased over the bundle's clients
 * as `docs/extending.md` describes: it answers from the same markers as the
 * scripted provider and logs which entry point the agents called.
 */
final readonly class CustomLlmClient implements LLMClientInterface
{
    /**
     * @throws InvalidTokenUsageException
     */
    #[Override]
    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        PlatformSession::record('custom-client complete');

        if (str_contains($userMessage, 'to Review')) {
            return $this->response((string) json_encode(array_map(
                static fn (string $id): array => ['id' => $id, 'accepted' => true],
                PromptReader::findingIds($userMessage),
            )));
        }

        return $this->response((string) json_encode(FindingMarkers::findingsIn($userMessage, $this->model())));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    #[Override]
    public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
    {
        $names = array_map(static fn (ToolDefinition $toolDefinition): string => $toolDefinition->name, $toolRegistry->definitions());
        PlatformSession::record(\sprintf('custom-client completeWithTools tools=%s', implode(',', $names)));

        if ($toolRegistry->has('record_review')) {
            foreach (PromptReader::findingIds($userMessage) as $id) {
                $toolRegistry->execute('record_review', ['id' => $id, 'accepted' => true, 'reviewer_notes' => 'ok']);
            }

            return $this->response('');
        }

        foreach (FindingMarkers::findingsIn($userMessage, $this->model()) as $finding) {
            $toolRegistry->execute('record_vulnerability', $finding);
        }

        return $this->response('');
    }

    #[Override]
    public function model(): string
    {
        return 'custom-model';
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function response(string $content): LLMResponse
    {
        return LLMResponse::of($content, $this->model(), 'end_turn', TokenUsageSnapshot::of(10, 5));
    }
}
