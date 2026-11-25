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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelListInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelNotice;

final class PulledModelNoticeTest extends TestCase
{
    public function test_it_names_each_configured_model_the_server_has_not_pulled(): void
    {
        $pulledModelNotice = new PulledModelNotice($this->serverPulling(['http://localhost:11434' => ['qwen3:latest', 'llama3.3:70b']]), 'http://localhost:11434', ['qwen9', 'qwen3', 'llama3.3']);

        self::assertSame(
            [
                'The Ollama server at http://localhost:11434 has not pulled the model "qwen9", so every call with it will fail. Run "ollama pull qwen9", or configure one of the models it pulled: qwen3:latest, llama3.3:70b.',
                'The Ollama server at http://localhost:11434 has not pulled the model "llama3.3", so every call with it will fail. Run "ollama pull llama3.3", or configure one of the models it pulled: qwen3:latest, llama3.3:70b.',
            ],
            $pulledModelNotice->notices(),
        );
    }

    /**
     * @param list<string> $models
     */
    #[DataProvider('nothingToSay')]
    public function test_it_says_nothing_when_it_cannot_tell_or_every_model_is_pulled(?string $endpoint, array $models): void
    {
        self::assertSame([], (new PulledModelNotice($this->serverPulling(['http://localhost:11434' => ['qwen3:latest', 'llama3.3:70b']]), $endpoint, $models))->notices());
    }

    /**
     * @return iterable<string, array{?string, list<string>}>
     */
    public static function nothingToSay(): iterable
    {
        yield 'every model pulled' => ['http://localhost:11434', ['qwen3', 'llama3.3:70b']];
        yield 'no endpoint configured' => [null, ['qwen9']];
        yield 'a server it cannot reach or that pulled nothing' => ['http://localhost:9', ['qwen9']];
    }

    /**
     * @param array<string, list<string>> $pulledModelsByEndpoint
     */
    private function serverPulling(array $pulledModelsByEndpoint): PulledModelListInterface
    {
        $pulledModelList = self::createStub(PulledModelListInterface::class);
        $pulledModelList->method('pulledModels')->willReturnCallback(static fn (string $endpoint): array => $pulledModelsByEndpoint[$endpoint] ?? []);

        return $pulledModelList;
    }
}
