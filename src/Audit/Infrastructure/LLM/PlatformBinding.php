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
 * The symfony/ai binding of one client, the part that differs between the
 * attacker, reviewer and cheap clients.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
        public ModelSetting $modelSetting = ModelSetting::Model,
    ) {}

    /**
     * @throws MissingAiPlatformException when no platform is bound, naming the ones configured
     */
    public function platform(): PlatformInterface
    {
        return $this->platform ?? throw MissingAiPlatformException::forUnselectedPlatforms($this->unselectedPlatforms);
    }
}
