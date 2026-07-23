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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\SelfUpdate\Fixture;

use Override;
use Psr\Log\AbstractLogger;
use Stringable;

final class RecordingLogger extends AbstractLogger
{
    /**
     * @var list<array<array-key, mixed>>
     */
    public array $contexts = [];

    /**
     * @param array<array-key, mixed> $context
     *
     * @throws void
     */
    #[Override]
    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        $this->contexts[] = $context;
    }

    /**
     * @return list<list<array-key>>
     */
    public function contextKeys(): array
    {
        return array_map(static fn (array $context): array => array_keys($context), $this->contexts);
    }
}
