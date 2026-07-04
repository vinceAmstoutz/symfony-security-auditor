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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * Renders the reviewer user messages (single finding and batch) — the
 * line-numbered finding report plus its closing instruction.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ReviewerMessageRendererInterface
{
    public function renderSingle(Vulnerability $vulnerability, string $codeContext, bool $useStructuredCollection): string;

    /**
     * @param list<Vulnerability>   $vulnerabilities
     * @param array<string, string> $codeContexts
     */
    public function renderBatch(array $vulnerabilities, array $codeContexts, bool $useStructuredCollection): string;
}
