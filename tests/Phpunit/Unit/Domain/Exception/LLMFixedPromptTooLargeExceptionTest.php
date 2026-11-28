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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Exception;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMFixedPromptTooLargeException;

final class LLMFixedPromptTooLargeExceptionTest extends TestCase
{
    public function test_a_caller_outside_the_class_names_the_file_its_size_and_the_reason_it_was_refused(): void
    {
        self::assertSame(
            'The audit prompt was refused even with only the 512-byte file "src/Kernel.php" in it (prompt is too long): the system prompt and the project mapping around it take up the rest, so no file can fit. Use a model with a larger context window for the attacker, raise audit.rate_limit.input_tokens_per_minute when that limit refused it, or narrow scan.included_paths.',
            LLMFixedPromptTooLargeException::forFile('src/Kernel.php', 512, 'prompt is too long')->getMessage(),
        );
    }
}
