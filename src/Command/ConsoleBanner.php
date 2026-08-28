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
 * The product identity line, shared by every entry point that shows it — the
 * `audit` command through `AuditPresenter::header()`, and every other
 * standalone-binary command through `StandaloneApplication::doRun()`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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

    /**
     * Brightened from the wordmark's `#242d5c` in `assets/banner.webp` — that
     * navy sits on the banner image's light background, but as terminal
     * foreground text it degrades toward black on a 16-colour palette and
     * disappears on the dark background most terminals default to.
     */
    private const string BANNER_NAVY = '#5b6fd6';

    /**
     * One code path for both terminal states: `OutputFormatter` drops the
     * style tags when the output is not decorated, so CI logs and a colour
     * terminal show the same layout rather than two different headers. Every
     * character is ASCII, so a Windows console on a legacy code page renders
     * it without substitution and without the double-width cells that break
     * column alignment.
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
     * `◉` is outside CP437/CP850/CP1252, so a console on a legacy code page
     * substitutes it. Dropping the mark there keeps the colour and the
     * wordmark, which carry the identity on their own.
     */
    private function scanMark(): string
    {
        return $this->consoleRendersUtf8() ? self::SCAN_MARK : self::SCAN_MARK_PORTABLE;
    }

    /**
     * The locale variables are the portable signal, and a Windows console
     * sets none of them unless the shell is UTF-8 aware — so Windows lands on
     * the ASCII wordmark without this needing a platform branch, which could
     * only ever be exercised on one platform's CI leg.
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
