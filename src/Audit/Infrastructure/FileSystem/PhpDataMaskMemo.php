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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem;

use Closure;

/**
 * The mask of the content a scrub has reached, built when a redaction first needs it and again
 * only once a pass has changed that content.
 *
 * Not readonly: keeps the mask across the passes of one scrub (stateful collaborator, see
 * .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class PhpDataMaskMemo
{
    private string $maskedContent = '';

    private ?PhpDataMask $phpDataMask = null;

    /**
     * @param Closure(string): PhpDataMask $phpDataMaskFactory
     */
    public function __construct(private readonly Closure $phpDataMaskFactory) {}

    public function of(string $content): PhpDataMask
    {
        if ($content !== $this->maskedContent) {
            $this->maskedContent = $content;
            $this->phpDataMask = null;
        }

        return $this->phpDataMask ??= ($this->phpDataMaskFactory)($content);
    }
}
