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

/** @internal not part of the BC promise — see docs/versioning.md */
final class MissingAiPlatformException extends LLMProviderException
{
    public static function create(): self
    {
        return new self('No AI platform is configured. Enable a platform (e.g. "anthropic") in config/packages/ai.yaml and set its API key — the symfony/ai-bundle recipe ships with every platform commented out.');
    }
}
