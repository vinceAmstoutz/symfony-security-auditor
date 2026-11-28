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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Override;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\StreamableInputInterface;

/** @internal not part of the BC promise, see docs/versioning.md */
final readonly class StandardInput implements StandardInputInterface
{
    #[Override]
    public function isTerminal(InputInterface $input): bool
    {
        $stream = $input instanceof StreamableInputInterface ? $input->getStream() : null;

        return stream_isatty($stream ?? \STDIN);
    }
}
