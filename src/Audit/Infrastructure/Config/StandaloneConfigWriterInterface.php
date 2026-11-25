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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

/**
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface StandaloneConfigWriterInterface
{
    /**
     * @param array<string, mixed>  $config
     * @param array<string, string> $comments a one-line comment to write above each top-level key named
     */
    public function write(string $configFile, array $config, array $comments = []): void;
}
