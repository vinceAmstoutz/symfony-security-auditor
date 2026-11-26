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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;

/** @internal not part of the BC promise, see docs/versioning.md */
final class UnobtainableIdentityTokenException extends LLMProviderException
{
    public static function fromGithubActions(int $status): self
    {
        return new self(\sprintf('GitHub Actions gave no identity token (HTTP %d): give the job the "id-token: write" permission.', $status));
    }

    public static function outsideGithubActions(): self
    {
        return new self('Workload identity federation reads the identity token from GitHub Actions: run in a job with the "id-token: write" permission, or set ANTHROPIC_API_KEY.');
    }
}
