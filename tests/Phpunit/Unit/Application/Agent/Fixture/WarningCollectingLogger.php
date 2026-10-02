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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture;

use Override;
use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use Stringable;

/**
 * Test fake: keeps every warning it is given as message and context, in order,
 * so a test can assert the exact warnings a run emitted without mocking the
 * logger.
 */
final class WarningCollectingLogger extends AbstractLogger
{
    /** @var list<array{string, array<mixed>}> */
    public array $warnings = [];

    /**
     * @param array<mixed> $context
     */
    #[Override]
    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        if (LogLevel::WARNING === $level) {
            $this->warnings[] = [(string) $message, $context];
        }
    }
}
