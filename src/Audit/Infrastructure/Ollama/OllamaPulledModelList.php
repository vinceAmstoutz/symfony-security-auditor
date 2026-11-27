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

use Override;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Asks an Ollama server which models it pulled, through its `/api/tags`,
 * giving up after WAIT_SECONDS.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class OllamaPulledModelList implements PulledModelListInterface
{
    private const float WAIT_SECONDS = 3.0;

    public function __construct(
        private HttpClientInterface $httpClient,
    ) {}

    #[Override]
    public function pulledModels(string $endpoint): array
    {
        try {
            $tags = $this->httpClient->request('GET', \sprintf('%s/api/tags', rtrim($endpoint, '/')), ['timeout' => self::WAIT_SECONDS, 'max_duration' => self::WAIT_SECONDS])->toArray();
        } catch (ExceptionInterface) {
            return [];
        }

        $names = [];
        foreach ((array) ($tags['models'] ?? []) as $model) {
            $name = \is_array($model) ? $model['name'] ?? null : null;
            if (\is_string($name)) {
                $names[] = $name;
            }
        }

        return $names;
    }
}
