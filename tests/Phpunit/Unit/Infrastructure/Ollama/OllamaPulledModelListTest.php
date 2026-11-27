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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Ollama;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\OllamaPulledModelList;

final class OllamaPulledModelListTest extends TestCase
{
    public function test_it_lists_the_models_the_server_pulled(): void
    {
        $mockHttpClient = new MockHttpClient(static fn (string $method, string $url): MockResponse => 'GET' === $method && 'http://localhost:11434/api/tags' === $url
            ? new MockResponse('{"models":[{"name":"qwen3:8b"},{"name":"llama3.3:latest"}]}')
            : new MockResponse('', ['http_code' => 404]));

        self::assertSame(['qwen3:8b', 'llama3.3:latest'], (new OllamaPulledModelList($mockHttpClient))->pulledModels('http://localhost:11434/'));
    }

    public function test_it_gives_up_on_a_server_that_does_not_answer_within_a_few_seconds(): void
    {
        $mockResponse = new MockResponse('{"models":[]}');

        (new OllamaPulledModelList(new MockHttpClient($mockResponse)))->pulledModels('http://localhost:11434');

        self::assertSame([3.0, 3.0], [$mockResponse->getRequestOptions()['timeout'], $mockResponse->getRequestOptions()['max_duration']]);
    }

    public function test_it_lists_nothing_when_the_server_cannot_be_reached(): void
    {
        $mockHttpClient = new MockHttpClient(new MockResponse('', ['error' => 'Connection refused']));

        self::assertSame([], (new OllamaPulledModelList($mockHttpClient))->pulledModels('http://localhost:11434'));
    }

    public function test_it_skips_an_entry_that_names_no_model(): void
    {
        $mockHttpClient = new MockHttpClient(new MockResponse('{"models":[{"name":"qwen3:8b"},{"size":1},"llama3.3",{"name":7}]}'));

        self::assertSame(['qwen3:8b'], (new OllamaPulledModelList($mockHttpClient))->pulledModels('http://localhost:11434'));
    }
}
