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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelListInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PricedModel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PricedModelListInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConfiguredModelCheck;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCheckResult;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DoctorCheckStatus;

final class ConfiguredModelCheckTest extends TestCase
{
    private const string PLACEHOLDER = 'The model claude-opus-5-5 is the placeholder init writes for a provider it cannot list models for. Set model: in config.yaml to a model the provider serves, or run init again with --model.';

    /**
     * @param array<array-key, mixed> $platform
     */
    #[DataProvider('placeholders')]
    public function test_it_warns_about_the_placeholder_model_on_a_provider_init_cannot_list_models_for(array $platform, ?string $provider): void
    {
        self::assertEquals([new DoctorCheckResult('Model', DoctorCheckStatus::Warning, self::PLACEHOLDER)], $this->check()->check($this->configuration($platform, $provider, ['model' => 'claude-opus-5-5'])));
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, ?string}>
     */
    public static function placeholders(): iterable
    {
        yield 'a gateway' => [['generic' => ['gw' => ['base_url' => 'https://gateway.example']]], 'generic.gw'];
        yield 'an Ollama server that lists no model' => [['ollama' => ['endpoint' => 'http://localhost:9']], 'ollama'];
        yield 'the only platform, selected by no provider' => [['mistral' => ['api_key' => 'k']], null];
    }

    /**
     * @param array<array-key, mixed> $platform
     * @param array<array-key, mixed> $auditConfig
     */
    #[DataProvider('modelsItCanVouchFor')]
    public function test_it_says_nothing_about_a_model_it_has_no_reason_to_doubt(array $platform, ?string $provider, array $auditConfig): void
    {
        self::assertSame([], $this->check()->check($this->configuration($platform, $provider, $auditConfig)));
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, ?string, array<array-key, mixed>}>
     */
    public static function modelsItCanVouchFor(): iterable
    {
        yield 'Anthropic' => [['anthropic' => ['api_key' => 'k']], 'anthropic', ['model' => 'claude-opus-5-5']];
        yield 'a priced provider' => [['openai' => ['api_key' => 'k']], 'openai', ['model' => 'claude-opus-5-5']];
        yield 'a subscription' => [['claudecode' => []], 'claudecode', ['model' => 'claude-opus-5-5']];
        yield 'another model on a gateway' => [['generic' => ['gw' => ['base_url' => 'https://gateway.example']]], 'generic.gw', ['model' => 'my-model']];
        yield 'pulled models' => [['ollama' => ['endpoint' => 'http://localhost:11434']], 'ollama', ['model' => 'qwen3', 'reviewer_model' => 'llama3.3:70b']];
        yield 'no model' => [['generic' => ['gw' => []]], 'generic.gw', []];
        yield 'a placeholder the Ollama server pulled' => [['ollama' => ['endpoint' => 'http://pulled.example:11434']], 'ollama', ['model' => 'claude-opus-5-5']];
    }

    public function test_it_warns_about_each_configured_model_a_reachable_ollama_server_has_not_pulled(): void
    {
        self::assertEquals(
            [
                new DoctorCheckResult('Model', DoctorCheckStatus::Warning, 'The Ollama server at http://localhost:11434 has not pulled the model "claude-opus-5-5", so every call with it will fail. Run "ollama pull claude-opus-5-5", or configure one of the models it pulled: qwen3:latest, llama3.3:70b.'),
                new DoctorCheckResult('Model', DoctorCheckStatus::Warning, 'The Ollama server at http://localhost:11434 has not pulled the model "qwen9", so every call with it will fail. Run "ollama pull qwen9", or configure one of the models it pulled: qwen3:latest, llama3.3:70b.'),
            ],
            $this->check()->check($this->configuration(['ollama' => ['endpoint' => 'http://localhost:11434']], 'ollama', ['model' => 'claude-opus-5-5', 'attacker_model' => 'qwen3', 'reviewer_model' => 'qwen9'])),
        );
    }

    public function test_it_asks_an_ollama_server_that_lists_no_model_once(): void
    {
        $pulledModelList = $this->createMock(PulledModelListInterface::class);
        $pulledModelList->expects(self::once())->method('pulledModels')->with('http://10.0.0.9:11434')->willReturn([]);

        (new ConfiguredModelCheck(self::createStub(PricedModelListInterface::class), $pulledModelList))->check($this->configuration(['ollama' => ['endpoint' => 'http://10.0.0.9:11434']], 'ollama', ['model' => 'claude-opus-5-5']));
    }

    private function check(): ConfiguredModelCheck
    {
        $pricedModelList = self::createStub(PricedModelListInterface::class);
        $pricedModelList->method('pricedModels')->willReturnCallback(static fn (string $platform): array => 'openai' === $platform ? [new PricedModel('gpt-5.6', 1.0, 2.0)] : []);
        $pulledModelList = self::createStub(PulledModelListInterface::class);
        $pulledModelList->method('pulledModels')->willReturnCallback(static fn (string $endpoint): array => ['http://localhost:11434' => ['qwen3:latest', 'llama3.3:70b'], 'http://pulled.example:11434' => ['claude-opus-5-5']][$endpoint] ?? []);

        return new ConfiguredModelCheck($pricedModelList, $pulledModelList);
    }

    /**
     * @param array<array-key, mixed> $platform
     * @param array<array-key, mixed> $auditConfig
     */
    private function configuration(array $platform, ?string $provider, array $auditConfig): StandaloneConfig
    {
        return new StandaloneConfig($auditConfig, new StandalonePlatformConfig($platform, $provider));
    }
}
