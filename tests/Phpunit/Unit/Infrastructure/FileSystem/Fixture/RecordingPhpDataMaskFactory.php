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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\FileSystem\Fixture;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\PhpDataMask;

/**
 * Builds each mask the way the scrubber does, remembering the content of every one it built.
 */
final class RecordingPhpDataMaskFactory
{
    /** @var list<string> */
    public array $maskedContents = [];

    public function __invoke(string $content): PhpDataMask
    {
        $this->maskedContents[] = $content;

        return PhpDataMask::of($content);
    }
}
