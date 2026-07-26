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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd\Fixture;

use Override;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\Template;
use Symfony\AI\Platform\Message\ToolCallMessage;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\AI\Platform\Tool\Tool;

/**
 * Deterministic {@see PlatformInterface} double that drives the full audit
 * pipeline through the real `SymfonyAiLLMClient` — retry, tool loop,
 * structured-collection wavefront and all — without any network call. Its
 * responses are derived from the prompt alone, so the same project fixture
 * always yields byte-identical findings regardless of profile.
 *
 * Attacker turns emit one `record_vulnerability` tool call per source file that
 * carries the {@see self::VULNERABLE_MARKER} sentinel; reviewer turns accept
 * every finding id present in the prompt via `record_review`; tool-free turns
 * (PoC / fix synthesis, or the JSON-array fallback path) return a fixed text.
 */
final class ScriptedAuditPlatform implements PlatformInterface
{
    public const string VULNERABLE_MARKER = 'SECURITY_AUDITOR_SINK';

    private const string PLAIN_TEXT_RESPONSE = 'curl -i https://app.example/admin';

    private readonly ModelCatalogInterface $modelCatalog;

    public function __construct()
    {
        $this->modelCatalog = new FallbackModelCatalog();
    }

    /**
     * @param array<array-key, mixed>|string|object $input
     * @param array<string, mixed>                  $options
     */
    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        return $this->deferred($this->resolve($input, $options), $options);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->modelCatalog;
    }

    /**
     * @param array<array-key, mixed>|string|object $input
     * @param array<string, mixed>                  $options
     */
    private function resolve(array|string|object $input, array $options): ResultInterface
    {
        $toolNames = $this->toolNames($options);

        if ($input instanceof MessageBag && $this->alreadyRanTools($input)) {
            return new TextResult('');
        }

        $prompt = $this->promptText($input);

        if (\in_array('record_review', $toolNames, true)) {
            return $this->reviewCalls($prompt);
        }

        if (\in_array('record_vulnerability', $toolNames, true)) {
            return $this->vulnerabilityCalls($prompt);
        }

        return $this->textPath($prompt);
    }

    private function reviewCalls(string $prompt): ResultInterface
    {
        preg_match_all('/VULN-[0-9A-F]{8}/', $prompt, $matches);
        $ids = array_values(array_unique($matches[0]));

        if ([] === $ids) {
            return new TextResult('');
        }

        $calls = [];
        foreach ($ids as $index => $id) {
            $calls[] = new ToolCall((string) $index, 'record_review', [
                'id' => $id,
                'accepted' => true,
                'reviewer_notes' => 'Confirmed exploitable in review.',
            ]);
        }

        return new ToolCallResult($calls);
    }

    private function vulnerabilityCalls(string $prompt): ResultInterface
    {
        $calls = [];
        foreach ($this->vulnerableFiles($prompt) as $index => $filePath) {
            $calls[] = new ToolCall((string) $index, 'record_vulnerability', $this->findingPayload($filePath));
        }

        if ([] === $calls) {
            return new TextResult('');
        }

        return new ToolCallResult($calls);
    }

    private function textPath(string $prompt): ResultInterface
    {
        if (str_contains($prompt, 'to Review')) {
            preg_match_all('/VULN-[0-9A-F]{8}/', $prompt, $matches);
            $reviews = array_map(
                static fn (string $id): array => ['id' => $id, 'accepted' => true, 'reviewer_notes' => 'Confirmed exploitable in review.'],
                array_values(array_unique($matches[0])),
            );

            return new TextResult((string) json_encode($reviews));
        }

        if (str_contains($prompt, self::VULNERABLE_MARKER)) {
            return new TextResult((string) json_encode(array_map(
                fn (string $filePath): array => $this->findingPayload($filePath),
                $this->vulnerableFiles($prompt),
            )));
        }

        return new TextResult(self::PLAIN_TEXT_RESPONSE);
    }

    /**
     * @return array<string, mixed>
     */
    private function findingPayload(string $filePath): array
    {
        return [
            'type' => 'broken_access_control',
            'severity' => 'critical',
            'title' => 'Unprotected administrative action',
            'description' => 'The controller action is reachable without any access-control check.',
            'file_path' => $filePath,
            'line_start' => 1,
            'line_end' => 1,
            'vulnerable_code' => 'public function delete(): Response',
            'attack_vector' => 'Any anonymous visitor can invoke the action directly.',
            'proof' => 'GET /admin/delete returns 200 for an unauthenticated client.',
            'remediation' => "Guard the action with #[IsGranted('ROLE_ADMIN')].",
            'confidence' => 0.95,
        ];
    }

    /**
     * @return list<string>
     */
    private function vulnerableFiles(string $prompt): array
    {
        preg_match_all('/<file path="([^"]+)"[^>]*>(.*?)<\/file>/s', $prompt, $matches, \PREG_SET_ORDER);

        $files = [];
        foreach ($matches as $match) {
            if (str_contains($match[2], self::VULNERABLE_MARKER)) {
                $files[] = $match[1];
            }
        }

        return array_values(array_unique($files));
    }

    private function alreadyRanTools(MessageBag $messageBag): bool
    {
        foreach ($messageBag->getMessages() as $message) {
            if ($message instanceof ToolCallMessage) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return list<string>
     */
    private function toolNames(array $options): array
    {
        $tools = $options['tools'] ?? [];
        if (!\is_array($tools)) {
            return [];
        }

        $names = [];
        foreach ($tools as $tool) {
            if ($tool instanceof Tool) {
                $names[] = $tool->getName();
            }
        }

        return $names;
    }

    /**
     * @param array<array-key, mixed>|string|object $input
     */
    private function promptText(array|string|object $input): string
    {
        if (\is_string($input)) {
            return $input;
        }

        if (!$input instanceof MessageBag) {
            return '';
        }

        $systemContent = $input->getSystemMessage()?->getContent();

        return ($systemContent instanceof Template ? '' : (string) $systemContent)
            .($input->getUserMessage()?->asText() ?? '');
    }

    /**
     * @param array<string, mixed> $options
     */
    private function deferred(ResultInterface $result, array $options): DeferredResult
    {
        $rawResult = $result->getRawResult() ?? new InMemoryRawResult(
            ['text' => ''],
            [],
            (object) ['text' => ''],
        );

        return new DeferredResult(new PlainConverter($result), $rawResult, $options);
    }
}
