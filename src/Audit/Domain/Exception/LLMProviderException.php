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
 * Base exception for LLM provider failures that must abort the audit.
 *
 * - **Non-transient** — missing platform configuration, auth failure, retired or
 *   unknown model. These repeat on every call and must never be swallowed.
 * - **Exhausted transient** — a retriable error (429, 5xx) whose retries are
 *   spent. The next chunk would fail the same way, so the audit aborts rather
 *   than returning a false-negative SAFE.
 *
 * Not final: the Infrastructure subclasses extend it so agents can catch it at
 * the Domain/Application boundary without importing Infrastructure types.
 */
class LLMProviderException extends RuntimeException {}
