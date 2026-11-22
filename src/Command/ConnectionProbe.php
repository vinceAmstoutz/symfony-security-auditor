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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;

/**
 * Sends the one short request `doctor --check-connection` makes.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConnectionProbe
{
    public const string FAILURE = 'The test failed, so an audit would fail too. The provider said: %s';

    private const string SYSTEM_PROMPT = 'You check that a connection works. Answer with the single word OK.';

    private const string USER_MESSAGE = 'Connection check';

    /**
     * @return ?string why the request failed, null when the provider answered
     */
    public function failureReason(LLMClientInterface $llmClient): ?string
    {
        try {
            $llmResponse = $llmClient->complete(self::SYSTEM_PROMPT, self::USER_MESSAGE);
        } catch (Throwable $throwable) {
            return $throwable->getMessage();
        }

        return $llmResponse->isDegraded()
            ? \sprintf('The provider answered, but its answer ended early (%s).', $llmResponse->stopReason())
            : null;
    }
}
