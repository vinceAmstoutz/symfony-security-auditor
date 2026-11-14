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
use Symfony\AI\Platform\Bridge\OpenAi\Factory;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final readonly class OpenAiStreamedProvider implements StreamedProviderInterface
{
    #[Override]
    public function servingPlatform(): string
    {
        return 'openai';
    }

    #[Override]
    public function model(): string
    {
        return 'gpt-4.1';
    }

    #[Override]
    public function platform(MockResponse ...$answers): PlatformInterface
    {
        return Factory::createPlatform('sk-test', new MockHttpClient($answers));
    }

    #[Override]
    public function textAnswer(string $text, int $inputTokens, int $outputTokens): MockResponse
    {
        return ServerSentEvents::of(
            ['type' => 'response.created', 'response' => ['id' => 'resp_1', 'status' => 'in_progress', 'output' => [], 'usage' => null]],
            ['type' => 'response.output_text.delta', 'delta' => $text],
            ['type' => 'response.completed', 'response' => [
                'id' => 'resp_1',
                'status' => 'completed',
                'model' => $this->model(),
                'output' => [['type' => 'message', 'id' => 'msg_1', 'role' => 'assistant', 'content' => [['type' => 'output_text', 'text' => $text]]]],
                'usage' => ['input_tokens' => $inputTokens, 'output_tokens' => $outputTokens, 'total_tokens' => $inputTokens + $outputTokens],
            ]],
        );
    }

    #[Override]
    public function askedForAStream(MockResponse $answer): bool
    {
        $body = $answer->getRequestOptions()['body'] ?? '';

        return \is_string($body) && str_contains($body, '"stream":true');
    }

    #[Override]
    public function toolCallAnswer(string $tool, array $arguments): MockResponse
    {
        $functionCall = ['type' => 'function_call', 'id' => 'fc_1', 'call_id' => 'call_1', 'name' => $tool, 'arguments' => json_encode($arguments, \JSON_THROW_ON_ERROR)];

        return ServerSentEvents::of(
            ['type' => 'response.created', 'response' => ['id' => 'resp_1', 'status' => 'in_progress', 'output' => [], 'usage' => null]],
            ['type' => 'response.output_item.added', 'output_index' => 0, 'item' => [...$functionCall, 'arguments' => '']],
            ['type' => 'response.function_call_arguments.delta', 'output_index' => 0, 'item_id' => 'fc_1', 'delta' => $functionCall['arguments']],
            ['type' => 'response.output_item.done', 'output_index' => 0, 'item' => $functionCall],
            ['type' => 'response.completed', 'response' => ['id' => 'resp_1', 'status' => 'completed', 'model' => $this->model(), 'output' => [$functionCall], 'usage' => ['input_tokens' => 100, 'output_tokens' => 5, 'total_tokens' => 105]]],
        );
    }
}
