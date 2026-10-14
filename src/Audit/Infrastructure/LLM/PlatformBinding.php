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

use Psr\Log\LoggerInterface;
use Symfony\AI\Platform\PlatformInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;

/**
 * The per-client symfony/ai binding: the platform handle, the model that
 * selects it, the logger, and the model's max-output-token cap. These are the
 * values that vary between the attacker / reviewer / cheap clients.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformBinding
{
    /**
     * @param list<string> $unselectedPlatforms the platform services the application configures when none is selected
     */
    public function __construct(
        public ?PlatformInterface $platform,
        public string $model,
        public LoggerInterface $logger,
        public ?int $maxOutputTokens = SymfonyAiLLMClient::DEFAULT_MAX_OUTPUT_TOKENS,
        public array $unselectedPlatforms = [],
    ) {}

    /**
     * @throws MissingAiPlatformException when no platform is bound, naming the ones configured
     */
    public function platform(): PlatformInterface
    {
        return $this->platform ?? throw MissingAiPlatformException::forUnselectedPlatforms($this->unselectedPlatforms);
    }
}
