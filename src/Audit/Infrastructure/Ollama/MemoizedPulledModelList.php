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

/**
 * Asks each Ollama server once, however often it is asked.
 *
 * Not `readonly`: it keeps the answers (`.claude/rules/php-classes.md`).
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class MemoizedPulledModelList implements PulledModelListInterface
{
    /** @var array<string, list<string>> */
    private array $pulledModelsByEndpoint = [];

    public function __construct(private readonly PulledModelListInterface $pulledModelList) {}

    #[Override]
    public function pulledModels(string $endpoint): array
    {
        return $this->pulledModelsByEndpoint[$endpoint] ??= $this->pulledModelList->pulledModels($endpoint);
    }
}
