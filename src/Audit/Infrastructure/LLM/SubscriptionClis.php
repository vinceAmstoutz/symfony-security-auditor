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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

/**
 * The CLIs an audit can run on a subscription through.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class SubscriptionClis
{
    /**
     * @var list<SubscriptionCliInterface>
     */
    private array $clis;

    public function __construct(SubscriptionCliInterface ...$clis)
    {
        $this->clis = array_values($clis);
    }

    public static function bundled(): self
    {
        return new self(new ClaudeCodeSubscriptionCli(), new CodexSubscriptionCli());
    }

    /**
     * Returns the CLI `provider:` names, or null for a provider billed per call.
     */
    public function of(string $platform): ?SubscriptionCliInterface
    {
        foreach ($this->clis as $cli) {
            if ($cli->platform() === $platform) {
                return $cli;
            }
        }

        return null;
    }
}
