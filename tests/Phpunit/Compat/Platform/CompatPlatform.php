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
use RuntimeException;
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
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd\Fixture\ScriptedAuditPlatform;

/**
 * The deterministic provider every compatibility scenario runs against, in the
 * pattern of the end-to-end {@see ScriptedAuditPlatform}:
 * its answers derive from the prompt and the {@see PlatformScript} alone, and
 * it logs one line per call so the request sequence can be compared.
 */
final readonly class CompatPlatform implements PlatformInterface
{
    private const int PROMPT_TOKENS = 100;

    private const int COMPLETION_TOKENS = 10;

    private const string PLAIN_TEXT_ANSWER = 'curl -i https://app.example/admin';

    public const string TOO_LONG_MARKER = 'COMPAT_PROMPT_TOO_LONG';

    private const string TOO_LONG_ANSWER = 'prompt is too long: 250000 tokens > 200000 maximum';

    private ModelCatalogInterface $modelCatalog;

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
        $failure = PlatformSession::script()->failure;
        if (null !== $failure && PlatformSession::countInvocation() > $failure[0]) {
            throw new RuntimeException($failure[1]);
        }

        $result = $this->resolve($model instanceof Model ? $model->getName() : $model, $input, $options);
        $rawResult = $result->getRawResult() ?? new InMemoryRawResult(['text' => ''], [], (object) ['text' => '']);
        $deferredResult = new DeferredResult(new PlainConverter($result), $rawResult, $options);
        $deferredResult->getMetadata()->add('token_usage', new TokenUsage(promptTokens: self::PROMPT_TOKENS, completionTokens: self::COMPLETION_TOKENS));

        return $deferredResult;
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
    private function resolve(string $model, array|string|object $input, array $options): ResultInterface
    {
        $toolNames = PromptReader::toolNames($options);
        $prompt = PromptReader::text($input);
        $toolResults = PromptReader::toolResultCount($input);

        if ($toolResults > 0) {
            PlatformSession::record(\sprintf('tool-results model=%s count=%d', $model, $toolResults));

            return new TextResult('');
        }

        if (str_contains($prompt, self::TOO_LONG_MARKER)) {
            PlatformSession::record(\sprintf('refused-too-long model=%s files=%s', $model, implode(',', array_keys(PromptReader::fileBlocks($prompt)))));

            throw new RuntimeException(self::TOO_LONG_ANSWER);
        }

        if (\in_array('record_review', $toolNames, true)) {
            return $this->reviewCalls($model, $prompt, $toolNames);
        }

        if (\in_array('record_vulnerability', $toolNames, true)) {
            return $this->attackerCalls($model, $prompt, $toolNames);
        }

        return $this->textAnswer($model, $prompt);
    }

    /**
     * @param list<string> $toolNames
     */
    private function reviewCalls(string $model, string $prompt, array $toolNames): ResultInterface
    {
        $ids = PromptReader::findingIds($prompt);
        PlatformSession::record(\sprintf('reviewer model=%s tools=%s findings=%d', $model, implode(',', $toolNames), \count($ids)));

        $calls = [];
        foreach ($ids as $index => $id) {
            $calls[] = new ToolCall(\sprintf('v%d', $index), 'record_review', ReviewVerdicts::verdictFor($id, $prompt));
        }

        return [] === $calls ? new TextResult('') : new ToolCallResult($calls);
    }

    /**
     * @param list<string> $toolNames
     */
    private function attackerCalls(string $model, string $prompt, array $toolNames): ResultInterface
    {
        PlatformSession::record(\sprintf('attacker model=%s tools=%s files=%s', $model, implode(',', $toolNames), implode(',', array_keys(PromptReader::fileBlocks($prompt)))));

        $calls = [];
        foreach (PlatformSession::takeAttackerToolCalls() as $index => [$tool, $arguments]) {
            $calls[] = new ToolCall(\sprintf('t%d', $index), $tool, $arguments);
        }

        if ([] !== $calls) {
            return new ToolCallResult($calls);
        }

        foreach (FindingMarkers::findingsIn($prompt, $model) as $index => $finding) {
            $calls[] = new ToolCall(\sprintf('c%d', $index), 'record_vulnerability', $finding);
        }

        return [] === $calls ? new TextResult('') : new ToolCallResult($calls);
    }

    private function textAnswer(string $model, string $prompt): ResultInterface
    {
        if (str_contains($prompt, 'to Review') || [] !== PromptReader::findingIds($prompt)) {
            PlatformSession::record(\sprintf('reviewer-json model=%s findings=%d', $model, \count(PromptReader::findingIds($prompt))));

            return new TextResult((string) json_encode(array_map(
                static fn (string $id): array => ReviewVerdicts::verdictFor($id, $prompt),
                PromptReader::findingIds($prompt),
            )));
        }

        $files = array_keys(PromptReader::fileBlocks($prompt));
        if ([] !== $files) {
            PlatformSession::record(\sprintf('attacker-json model=%s files=%s', $model, implode(',', $files)));

            return new TextResult((string) json_encode(FindingMarkers::findingsIn($prompt, $model)));
        }

        PlatformSession::record(\sprintf('text model=%s', $model));

        return new TextResult(self::PLAIN_TEXT_ANSWER);
    }
}
