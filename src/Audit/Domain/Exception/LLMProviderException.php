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
 * Covers two cases:
 * - **Non-transient** — missing platform configuration, auth failure, retired/unknown
 *   model. These repeat on every subsequent call and must never be swallowed.
 * - **Exhausted transient** — a retriable error (rate-limit 429, 5xx) where every
 *   retry has been exhausted. Continuing to the next chunk would produce the same
 *   failure, so the audit must also abort rather than returning a false-negative SAFE.
 *
 * Not final: Infrastructure-layer subclasses (`NonTransientLLMFailureException`,
 * `TransientLLMFailureException`) extend this exception so agents can catch it at
 * the Domain/Application boundary without importing Infrastructure types. The
 * one subclass an agent recovers from is `LLMRequestTooLargeException`: a prompt
 * the model cannot take in fails only that chunk, which is split and retried.
 */
class LLMProviderException extends RuntimeException {}
