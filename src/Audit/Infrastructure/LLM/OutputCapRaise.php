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

use Symfony\AI\Platform\PlatformOptions;

/**
 * The options of a tool request asked again after the output cap cut its tool
 * call off: the same request with twice the cap. Null for a request that
 * offered no tool or sent no cap, which a higher cap cannot help.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class OutputCapRaise
{
    private const int FACTOR = 2;

    /** @var list<string> */
    private const array CAP_OPTIONS = [PlatformOptions::MAX_OUTPUT_TOKENS, 'max_tokens'];

    /**
     * @param array<string, mixed> $options
     *
     * @return array<string, mixed>|null
     */
    public function raised(array $options): ?array
    {
        if (!\array_key_exists('tools', $options)) {
            return null;
        }

        foreach (self::CAP_OPTIONS as $capOption) {
            $cap = $options[$capOption] ?? null;
            if (\is_int($cap)) {
                $options[$capOption] = $cap * self::FACTOR;

                return $options;
            }
        }

        return null;
    }
}
