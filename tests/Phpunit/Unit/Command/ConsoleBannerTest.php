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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Formatter\OutputFormatterInterface;
use Symfony\Component\Console\Output\BufferedOutput;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConsoleBanner;

final class ConsoleBannerTest extends TestCase
{
    public function test_it_shows_the_mark_and_wordmark_in_the_brand_palette_when_decorated(): void
    {
        $display = $this->bannerIn(['LC_ALL' => 'en_US.UTF-8'], true);
        $outputFormatter = (new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, true))->getFormatter();

        self::assertStringContainsString($this->formatted($outputFormatter, '<fg=#e71c55;options=bold>◉ >> SECURITY</>'), $display);
        self::assertStringContainsString($this->formatted($outputFormatter, '<fg=#5b6fd6;options=bold>AUDITOR</>'), $display);
        self::assertStringStartsWith(\PHP_EOL, $display, 'the banner must not abut whatever printed before it');
    }

    public function test_it_keeps_the_same_layout_without_colour_when_not_decorated(): void
    {
        $display = $this->bannerIn(['LC_ALL' => 'en_US.UTF-8'], false);

        self::assertStringContainsString(' ◉ >> SECURITY AUDITOR', $display);
        self::assertStringContainsString('Symfony - multi-agent LLM audit', $display);
        self::assertStringNotContainsString("\033[", $display, 'CI output must carry no escape sequences');
    }

    #[DataProvider('alignedLines')]
    public function test_every_line_under_the_wordmark_starts_where_the_wordmark_does(int $line, string $needle): void
    {
        $lines = explode(\PHP_EOL, $this->bannerIn(['LC_ALL' => 'en_US.UTF-8'], false));

        self::assertSame(
            mb_strpos($lines[1], 'SECURITY'),
            mb_strpos($lines[$line], $needle),
            'the offset is derived from the lead string, so it tracks the mark width',
        );
    }

    /** @return iterable<string, array{int, string}> */
    public static function alignedLines(): iterable
    {
        yield 'the tagline' => [2, 'Symfony'];
        yield 'the homepage' => [3, 'https://'];
    }

    #[DataProvider('consoleModes')]
    public function test_it_points_at_the_project_homepage(bool $decorated): void
    {
        self::assertStringContainsString(
            'https://github.com/vinceAmstoutz/symfony-security-auditor',
            $this->bannerIn(['LC_ALL' => 'en_US.UTF-8'], $decorated),
        );
    }

    public function test_a_console_without_utf8_drops_the_mark_and_keeps_the_wordmark(): void
    {
        $display = $this->bannerIn(['LC_ALL' => 'C'], false);

        self::assertStringNotContainsString('◉', $display, 'the mark is outside CP437/CP850/CP1252 and would be substituted');
        self::assertStringContainsString(' SECURITY AUDITOR', $display);
        self::assertStringContainsString('Symfony - multi-agent LLM audit', $display);
    }

    public function test_a_console_without_utf8_still_gets_the_brand_palette(): void
    {
        $display = $this->bannerIn(['LC_ALL' => 'C'], true);
        $outputFormatter = (new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, true))->getFormatter();

        self::assertStringContainsString($this->formatted($outputFormatter, '<fg=#e71c55;options=bold>SECURITY</>'), $display);
        self::assertStringContainsString($this->formatted($outputFormatter, '<fg=#5b6fd6;options=bold>AUDITOR</>'), $display);
    }

    /**
     * @param array<string, string> $locale
     */
    #[DataProvider('utf8Announcements')]
    public function test_any_locale_variable_announcing_utf8_earns_the_mark(array $locale): void
    {
        self::assertStringContainsString('◉', $this->bannerIn($locale, false));
    }

    /** @return iterable<string, array{array<string, string>}> */
    public static function utf8Announcements(): iterable
    {
        yield 'LC_ALL' => [['LC_ALL' => 'en_US.UTF-8']];
        yield 'LC_CTYPE only' => [['LC_CTYPE' => 'en_US.UTF-8']];
        yield 'LANG only' => [['LANG' => 'en_US.UTF-8']];
        yield 'lowercase spelling' => [['LANG' => 'en_us.utf-8']];
        yield 'unhyphenated spelling' => [['LANG' => 'en_US.utf8']];
        yield 'an empty variable defers to the next one' => [['LC_ALL' => '', 'LC_CTYPE' => 'en_US.UTF-8']];
    }

    public function test_a_console_that_announces_no_locale_at_all_drops_the_mark(): void
    {
        $display = $this->bannerIn([], false);

        self::assertStringNotContainsString('◉', $display);
        self::assertStringContainsString(' SECURITY AUDITOR', $display);
    }

    #[DataProvider('consoleModes')]
    public function test_the_banner_is_pure_ascii_without_utf8_support(bool $decorated): void
    {
        $withoutEscapes = (string) preg_replace('/\033\[[0-9;]*m/', '', $this->bannerIn(['LC_ALL' => 'C'], $decorated));

        self::assertMatchesRegularExpression('/^[\x00-\x7F]*$/', $withoutEscapes);
    }

    /** @return iterable<string, array{bool}> */
    public static function consoleModes(): iterable
    {
        yield 'decorated' => [true];
        yield 'plain' => [false];
    }

    /**
     * Every locale variable is pinned individually, and any not named is
     * cleared: setting all three to one value hides which of them the banner
     * actually read.
     *
     * @param array<string, string> $locale
     */
    private function bannerIn(array $locale, bool $decorated): string
    {
        $variables = ['LC_ALL', 'LC_CTYPE', 'LANG'];
        $previous = [];

        foreach ($variables as $variable) {
            $previous[$variable] = getenv($variable);
            $value = $locale[$variable] ?? null;
            putenv(null === $value ? $variable : \sprintf('%s=%s', $variable, $value));
        }

        try {
            $bufferedOutput = new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, $decorated);
            (new ConsoleBanner())->render($bufferedOutput);

            return $bufferedOutput->fetch();
        } finally {
            foreach ($variables as $variable) {
                $restored = $previous[$variable];
                putenv(false === $restored ? $variable : \sprintf('%s=%s', $variable, $restored));
            }
        }
    }

    private function formatted(OutputFormatterInterface $outputFormatter, string $tag): string
    {
        $formatted = $outputFormatter->format($tag);
        self::assertNotNull($formatted);

        return $formatted;
    }
}
