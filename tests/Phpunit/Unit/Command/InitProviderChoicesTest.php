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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitProviderChoices;

final class InitProviderChoicesTest extends TestCase
{
    public function test_it_lists_the_priced_platforms_a_bare_name_configures_and_the_subscription_clis_in_alphabetical_order(): void
    {
        self::assertSame(
            ['anthropic', 'cerebras', 'claudecode', 'codex', 'cohere', 'deepseek', 'edenai', 'fireworks', 'gemini', 'huggingface', 'minimax', 'mistral', 'openai', 'openrouter', 'ovh', 'perplexity', 'scaleway', 'together', 'venice', 'vertexai'],
            InitProviderChoices::names(),
        );
    }
}
