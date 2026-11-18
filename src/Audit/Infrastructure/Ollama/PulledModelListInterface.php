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
 * The models an Ollama server has pulled, for `init` to offer.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface PulledModelListInterface
{
    /**
     * @return list<string> empty when the server cannot be reached or holds none
     */
    public function pulledModels(string $endpoint): array;
}
