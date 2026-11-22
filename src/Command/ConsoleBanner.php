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
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The product identity banner.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConsoleBanner implements ConsoleBannerInterface
{
    private const string SCAN_MARK = '◉ >>';

    private const string SCAN_MARK_PORTABLE = '';

    private const string WORDMARK_LEAD = 'SECURITY';

    private const string WORDMARK_TAIL = 'AUDITOR';

    private const string TAGLINE = 'Symfony - multi-agent LLM audit';

    private const string HOMEPAGE = 'https://github.com/vinceAmstoutz/symfony-security-auditor';

    /** Sampled from the circular bug glyph in `assets/banner.webp`. */
    private const string BANNER_PINK = '#e71c55';

    /** Brighter than the wordmark's `#242d5c`, which vanishes on a dark terminal. */
    private const string BANNER_NAVY = '#5b6fd6';

    /**
     * Prints the same layout whether the output is decorated or not.
     */
    #[Override]
    public function render(OutputInterface $output): void
    {
        $scanMark = $this->scanMark();
        $markedLead = '' === $scanMark ? '' : \sprintf('%s ', $scanMark);

        $output->writeln([
            '',
            \sprintf(
                ' <fg=%s;options=bold>%s%s</> <fg=%s;options=bold>%s</>',
                self::BANNER_PINK,
                $markedLead,
                self::WORDMARK_LEAD,
                self::BANNER_NAVY,
                self::WORDMARK_TAIL,
            ),
            $this->alignedUnderWordmark($markedLead, self::TAGLINE),
            $this->alignedUnderWordmark($markedLead, \sprintf('<fg=gray>%s</>', self::HOMEPAGE)),
            '',
        ]);
    }

    private function alignedUnderWordmark(string $markedLead, string $line): string
    {
        return \sprintf(' %s%s', str_repeat(' ', mb_strlen($markedLead)), $line);
    }

    /**
     * `◉` is outside the CP437, CP850 and CP1252 code pages.
     */
    private function scanMark(): string
    {
        return $this->consoleRendersUtf8() ? self::SCAN_MARK : self::SCAN_MARK_PORTABLE;
    }

    /**
     * A Windows console sets no locale variable unless its shell is UTF-8
     * aware.
     */
    private function consoleRendersUtf8(): bool
    {
        $locale = strtoupper($this->localeSetting());

        return str_contains($locale, 'UTF-8') || str_contains($locale, 'UTF8');
    }

    private function localeSetting(): string
    {
        foreach (['LC_ALL', 'LC_CTYPE', 'LANG'] as $variable) {
            $value = getenv($variable);
            if (\is_string($value) && '' !== $value) {
                return $value;
            }
        }

        return '';
    }
}
