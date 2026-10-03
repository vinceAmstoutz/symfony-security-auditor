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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command\Fixture;

use Override;
use Symfony\Component\Console\Exception\RuntimeException;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Behaves like Console on a terminal without `stty`: hiding the answer is
 * impossible, and with the echo fallback disabled the question helper throws.
 */
final class UnhideableSymfonyStyle extends SymfonyStyle
{
    #[Override]
    public function askQuestion(Question $question): mixed
    {
        throw new RuntimeException('Unable to hide the response.');
    }
}
