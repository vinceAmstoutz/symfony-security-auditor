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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\Stream;

use Override;
use Symfony\AI\Platform\Bridge\Gemini\Factory;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final readonly class GeminiStreamedProvider implements StreamedProviderInterface
{
    #[Override]
    public function servingPlatform(): string
    {
        return 'gemini';
    }

    #[Override]
    public function model(): string
    {
        return 'gemini-2.5-flash';
    }

    #[Override]
    public function platform(MockResponse ...$answers): PlatformInterface
    {
        return Factory::createPlatform('sk-test', new MockHttpClient($answers));
    }

    #[Override]
    public function textAnswer(string $text, int $inputTokens, int $outputTokens): MockResponse
    {
        $usage = ['promptTokenCount' => $inputTokens, 'candidatesTokenCount' => $outputTokens, 'totalTokenCount' => $inputTokens + $outputTokens];

        return ServerSentEvents::of(
            ['candidates' => [['content' => ['role' => 'model', 'parts' => [['text' => $text]]], 'index' => 0]], 'usageMetadata' => ['promptTokenCount' => $inputTokens, 'candidatesTokenCount' => 1, 'totalTokenCount' => $inputTokens + 1], 'modelVersion' => $this->model()],
            ['candidates' => [['content' => ['role' => 'model', 'parts' => [['text' => '']]], 'finishReason' => 'STOP', 'index' => 0]], 'usageMetadata' => $usage, 'modelVersion' => $this->model()],
        );
    }

    #[Override]
    public function askedForAStream(MockResponse $answer): bool
    {
        return str_contains($answer->getRequestUrl(), ':streamGenerateContent');
    }

    #[Override]
    public function toolCallAnswer(string $tool, array $arguments): MockResponse
    {
        return ServerSentEvents::of(
            ['candidates' => [['content' => ['role' => 'model', 'parts' => [['functionCall' => ['id' => 'call_1', 'name' => $tool, 'args' => $arguments]]]], 'finishReason' => 'STOP', 'index' => 0]], 'usageMetadata' => ['promptTokenCount' => 100, 'candidatesTokenCount' => 5, 'totalTokenCount' => 105], 'modelVersion' => $this->model()],
        );
    }
}
