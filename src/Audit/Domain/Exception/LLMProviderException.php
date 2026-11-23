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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception;

use RuntimeException;

/**
 * An LLM provider failure that aborts the audit, never swallowed: a
 * non-transient one (missing platform configuration, auth failure, unknown
 * model) or a transient one (429, 5xx) whose retries are spent. Going on would
 * report a false SAFE.
 *
 * Not final: Infrastructure subclasses extend it. The one subclass an agent
 * recovers from is `LLMRequestTooLargeException`.
 */
class LLMProviderException extends RuntimeException {}
