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
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Keeps the question it was asked, so a test can inspect how it was configured.
 */
final class RecordingSymfonyStyle extends SymfonyStyle
{
    public ?Question $question = null;

    #[Override]
    public function askQuestion(Question $question): mixed
    {
        $this->question = $question;

        return 'anthropic-test-key-recorded';
    }
}
