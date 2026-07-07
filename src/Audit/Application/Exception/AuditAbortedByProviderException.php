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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception;

use Override;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/**
 * Signals that an audit was halted by a non-transient LLM provider failure
 * (misconfiguration, auth error, retired model). Carries the partial
 * `AuditReport` collected up to the abort point so the command layer can
 * still render whatever findings were validated before the provider failed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class AuditAbortedByProviderException extends RuntimeException implements AuditAbortedExceptionInterface
{
    private function __construct(string $message, private readonly AuditReport $auditReport, LLMProviderException $llmProviderException)
    {
        parent::__construct($message, previous: $llmProviderException);
    }

    public static function from(LLMProviderException $llmProviderException, AuditReport $auditReport): self
    {
        return new self($llmProviderException->getMessage(), $auditReport, $llmProviderException);
    }

    #[Override]
    public function partialReport(): AuditReport
    {
        return $this->auditReport;
    }
}
