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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class StaleBridgeTreeException extends RuntimeException
{
    /**
     * `init --force` replaces the provider, platform and model, so the advice
     * says it will want the model and connection options again rather than
     * letting it fall back to its defaults.
     */
    public static function forTree(string $directory, string $treeVersion, string $bundledVersion, ?string $provider): self
    {
        return new self(\sprintf(
            'The provider bridge under "%1$s" was installed for symfony/ai-platform %2$s, but this binary bundles %3$s: loaded, its classes would replace the bundled ones and fail every LLM call, so the binary leaves it unloaded. Rebuild it with "symfony-security-auditor init --provider=%4$s --force" — init rewrites config.yaml, so give it your model and connection options again.',
            $directory,
            $treeVersion,
            $bundledVersion,
            $provider ?? '<platform>',
        ));
    }
}
