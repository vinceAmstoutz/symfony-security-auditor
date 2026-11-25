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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama;

/**
 * Names each configured model an Ollama server has not pulled. Says nothing
 * when no endpoint is configured or the server lists no model, which it
 * cannot tell from a server it cannot reach.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PulledModelNotice
{
    private const string DEFAULT_TAG = ':latest';

    /**
     * @param list<string> $models
     */
    public function __construct(
        private PulledModelListInterface $pulledModelList,
        private ?string $endpoint,
        private array $models,
    ) {}

    /**
     * A model named without a tag is pulled when its `latest` tag is.
     *
     * @param list<string> $pulledModels
     */
    public static function isPulled(string $model, array $pulledModels): bool
    {
        return \in_array($model, $pulledModels, true) || \in_array($model.self::DEFAULT_TAG, $pulledModels, true);
    }

    /**
     * @return list<string>
     */
    public function notices(): array
    {
        $pulledModels = null === $this->endpoint ? [] : $this->pulledModelList->pulledModels($this->endpoint);
        if ([] === $pulledModels) {
            return [];
        }

        $notices = [];
        foreach ($this->models as $model) {
            if (!self::isPulled($model, $pulledModels)) {
                $notices[] = \sprintf('The Ollama server at %s has not pulled the model "%s", so every call with it will fail. Run "ollama pull %2$s", or configure one of the models it pulled: %s.', $this->endpoint, $model, implode(', ', $pulledModels));
            }
        }

        return $notices;
    }
}
