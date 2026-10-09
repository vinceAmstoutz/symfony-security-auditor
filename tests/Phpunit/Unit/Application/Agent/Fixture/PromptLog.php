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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

final class PromptLog
{
    /** @var list<array{prompt: string, offersRecordReview: bool}> */
    public array $calls = [];

    public function record(string $systemPrompt, string $userMessage, ?ToolRegistry $toolRegistry): void
    {
        $this->calls[] = [
            'prompt' => $systemPrompt."\n".$userMessage,
            'offersRecordReview' => $toolRegistry instanceof ToolRegistry && $toolRegistry->has('record_review'),
        ];
    }
}
