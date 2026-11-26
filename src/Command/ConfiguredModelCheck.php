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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CliAgentPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PlatformApiKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\MemoizedPulledModelList;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelListInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelNotice;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PricedModelListInterface;

/**
 * Warns about a configured model the run is likely to be refused: the
 * placeholder `init --no-interaction` writes for a provider it cannot list
 * models for, or a model a reachable Ollama server has not pulled.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConfiguredModelCheck
{
    private const string LABEL = 'Model';

    private const array MODEL_KEYS = ['model', 'attacker_model', 'reviewer_model'];

    private const string OLLAMA = 'ollama';

    private const string ENDPOINT = 'endpoint';

    public function __construct(
        private PricedModelListInterface $pricedModelList,
        private PulledModelListInterface $pulledModelList,
    ) {}

    /**
     * @return list<DoctorCheckResult>
     */
    public function check(StandaloneConfig $standaloneConfig): array
    {
        $platform = $this->platformOf($standaloneConfig);
        $models = $this->modelsOf($standaloneConfig);
        $endpoint = self::OLLAMA === $platform ? $this->endpointOf($standaloneConfig) : null;
        $pulledModelList = new MemoizedPulledModelList($this->pulledModelList);
        $notices = (new PulledModelNotice($pulledModelList, $endpoint, $models))->notices();

        if ([] === $notices && $this->writesAPlaceholder($platform, $models, $endpoint, $pulledModelList)) {
            $notices = [\sprintf('The model %s is the placeholder init writes for a provider it cannot list models for. Set model: in config.yaml to a model the provider serves, or run init again with --model.', PlaceholderModel::MODEL)];
        }

        return array_map(static fn (string $notice): DoctorCheckResult => new DoctorCheckResult(self::LABEL, DoctorCheckStatus::Warning, $notice), $notices);
    }

    /**
     * @param list<string> $models
     */
    private function writesAPlaceholder(string $platform, array $models, ?string $endpoint, PulledModelListInterface $pulledModelList): bool
    {
        return \in_array(PlaceholderModel::MODEL, $models, true) && !$this->listsModelsOf($platform, $endpoint, $pulledModelList);
    }

    private function listsModelsOf(string $platform, ?string $endpoint, PulledModelListInterface $pulledModelList): bool
    {
        if (self::OLLAMA === $platform) {
            return null !== $endpoint && [] !== $pulledModelList->pulledModels($endpoint);
        }

        return 'anthropic' === $platform || CliAgentPlatforms::declares(ProviderKey::of($platform)) || [] !== $this->pricedModelList->pricedModels($platform);
    }

    private function platformOf(StandaloneConfig $standaloneConfig): string
    {
        $provider = $standaloneConfig->platform->activeProvider ?? (string) array_key_first($standaloneConfig->platform->platform);

        return ProviderKey::of($provider)->platform;
    }

    /**
     * @return list<string>
     */
    private function modelsOf(StandaloneConfig $standaloneConfig): array
    {
        $models = array_filter(array_map(static fn (string $key): mixed => $standaloneConfig->auditConfig[$key] ?? null, self::MODEL_KEYS), \is_string(...));

        return array_values(array_unique($models));
    }

    private function endpointOf(StandaloneConfig $standaloneConfig): ?string
    {
        $endpoint = PlatformApiKey::blockForProvider($standaloneConfig->platform->platform, self::OLLAMA)[self::ENDPOINT] ?? null;

        return \is_string($endpoint) ? $endpoint : null;
    }
}
