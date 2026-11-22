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

use Symfony\AI\Platform\Bridge\ClaudeCode\Factory as ClaudeCodeFactory;
use Symfony\AI\Platform\Bridge\ClaudeCode\ModelCatalog as ClaudeCodeModelCatalog;
use Symfony\AI\Platform\Bridge\Codex\Factory as CodexFactory;
use Symfony\AI\Platform\Bridge\Codex\ModelCatalog as CodexModelCatalog;
use Symfony\AI\Platform\Platform;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Builds the platform of a coding agent's CLI, started in a directory of its
 * own that only the user running the audit can open: the CLI reads its
 * settings, hooks included, from the directory it starts in, so a shared one
 * such as the system temp directory would let another local user configure
 * it.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CliAgentPlatformFactory
{
    private const int PRIVATE_DIRECTORY_MODE = 0o700;

    /**
     * The models each CLI offers a subscription, the suggested one first.
     */
    public const array SUBSCRIPTION_MODELS = [
        'claudecode' => ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5'],
        'codex' => ['gpt-5.4', 'gpt-5.4-mini', 'gpt-5.3-codex'],
    ];

    /**
     * @param class-string<ClaudeCodeFactory>|class-string<CodexFactory> $bridgeFactory
     */
    public static function create(string $bridgeFactory, ?string $cliBinary): Platform
    {
        $workingDirectory = \sprintf('%s/symfony-security-auditor-cli-%s', sys_get_temp_dir(), bin2hex(random_bytes(16)));
        (new Filesystem())->mkdir($workingDirectory, self::PRIVATE_DIRECTORY_MODE);

        return $bridgeFactory::createPlatform($cliBinary, $workingDirectory, modelCatalog: self::modelCatalogFor($bridgeFactory));
    }

    /**
     * @param class-string<ClaudeCodeFactory>|class-string<CodexFactory> $bridgeFactory
     */
    private static function modelCatalogFor(string $bridgeFactory): CliAgentModelCatalog
    {
        return ClaudeCodeFactory::class === $bridgeFactory
            ? new CliAgentModelCatalog(new ClaudeCodeModelCatalog(), 'opus')
            : new CliAgentModelCatalog(new CodexModelCatalog(), 'gpt-5.4');
    }
}
