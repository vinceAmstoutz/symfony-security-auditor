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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory\Fixture;

use Override;
use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use Stringable;

final class WarningRecordingLogger extends AbstractLogger
{
    /**
     * @var list<array{string, array<array-key, mixed>}>
     */
    public array $warnings = [];

    /**
     * @param array<array-key, mixed> $context
     */
    #[Override]
    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        if (LogLevel::WARNING === $level) {
            $this->warnings[] = [(string) $message, $context];
        }
    }
}
