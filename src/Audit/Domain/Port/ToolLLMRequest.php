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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * One tool-using conversation bound for a tool-batch-capable client. Separate
 * from {@see LLMRequest} so the registry is never nullable.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ToolLLMRequest
{
    public function __construct(
        public string $system,
        public string $user,
        public ToolRegistry $tools,
    ) {}

    /**
     * @param list<array{system: string, user: string, tools: ToolRegistry}> $requests
     *
     * @return list<self>
     */
    public static function listFromArrays(array $requests): array
    {
        return array_map(
            static fn (array $request): self => new self($request['system'], $request['user'], $request['tools']),
            $requests,
        );
    }
}
