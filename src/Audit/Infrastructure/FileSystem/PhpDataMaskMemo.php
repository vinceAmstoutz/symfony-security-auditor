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
 * The mask of the content one scrub has reached, built the first time a redaction needs it and
 * built again only once a pass has changed that content: tokenizing a file costs more than every
 * pattern that finds nothing in it.
 *
 * Mutable by design: it keeps a lazily built mask across the passes of one scrub, so it opts out
 * of the final readonly rule as a stateful collaborator (see .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
