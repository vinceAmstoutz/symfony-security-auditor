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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NestingDepthGuard;

final class NestingDepthGuardTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_admits_a_file_nested_exactly_to_the_limit(): void
    {
        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('warning');

        $admitted = (new NestingDepthGuard($logger))->admits($this->fileWith(str_repeat('(', 200).str_repeat(')', 200)));

        self::assertTrue($admitted);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_refuses_a_file_nested_one_level_past_the_limit_and_names_it_in_a_warning(): void
    {
        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('nest too deeply'),
                self::identicalTo(['file' => 'src/Controller/X.php', 'max_nesting_depth' => 200]),
            );

        $admitted = (new NestingDepthGuard($logger))->admits($this->fileWith(str_repeat('(', 201).str_repeat(')', 201)));

        self::assertFalse($admitted);
    }

    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('closersPastTheLimit')]
    public function test_it_refuses_a_file_holding_a_flood_of_unmatched_closers_and_names_it_in_a_warning(string $closer): void
    {
        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('unmatched closing brackets'),
                self::identicalTo(['file' => 'src/Controller/X.php', 'max_unmatched_closers' => 1000]),
            );

        $admitted = (new NestingDepthGuard($logger))->admits($this->fileWith(str_repeat($closer, 16000)));

        self::assertFalse($admitted);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function closersPastTheLimit(): iterable
    {
        yield 'parentheses' => [')'];
        yield 'square brackets' => [']'];
        yield 'curly braces' => ['}'];
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_admits_a_file_holding_as_many_unmatched_closers_as_the_limit_and_refuses_one_more(): void
    {
        $nestingDepthGuard = new NestingDepthGuard();

        self::assertTrue($nestingDepthGuard->admits($this->fileWith(str_repeat(')', 1000))));
        self::assertFalse($nestingDepthGuard->admits($this->fileWith(str_repeat(')', 1001))));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function nestingConstructsPastTheLimit(): iterable
    {
        yield 'parentheses' => [str_repeat('(', 201)];
        yield 'square brackets' => [str_repeat('[', 201)];
        yield 'curly braces' => [str_repeat('{', 201)];
        yield 'interpolated expressions' => [str_repeat('"{$a', 201)];
        yield 'dollar-brace interpolations' => [str_repeat('"${a', 201)];
        yield 'attributes' => [str_repeat('#[A', 201)];
    }

    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('nestingConstructsPastTheLimit')]
    public function test_it_counts_every_kind_of_opening_bracket_even_when_never_closed(string $nesting): void
    {
        self::assertFalse((new NestingDepthGuard())->admits($this->fileWith($nesting)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function manySiblingGroups(): iterable
    {
        yield 'parentheses' => [str_repeat('f(1);', 250)];
        yield 'square brackets' => [str_repeat('[1];', 250)];
        yield 'curly braces' => [str_repeat('{}', 250)];
    }

    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('manySiblingGroups')]
    public function test_it_does_not_count_brackets_that_have_been_closed(string $siblings): void
    {
        self::assertTrue((new NestingDepthGuard())->admits($this->fileWith($siblings)));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_measures_the_deepest_point_reached_after_partially_closing_a_group(): void
    {
        $nesting = str_repeat('(', 150).str_repeat(')', 10).str_repeat('(', 61);

        self::assertFalse((new NestingDepthGuard())->admits($this->fileWith($nesting)));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_brackets_inside_string_literals_comments_and_inline_html(): void
    {
        $brackets = str_repeat('([{', 100);
        $source = <<<PHP
            <?php
            \$single = '{$brackets}';
            \$double = "{$brackets}";
            // {$brackets}
            # {$brackets}
            /* {$brackets} */
            \$heredoc = <<<TEXT
            {$brackets}
            TEXT;
            ?>
            {$brackets}
            PHP;

        self::assertTrue((new NestingDepthGuard())->admits($this->fileHolding($source)));
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function fileWith(string $code): ProjectFile
    {
        return $this->fileHolding('<?php '.$code);
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function fileHolding(string $source): ProjectFile
    {
        return ProjectFile::create('src/Controller/X.php', '/app/src/Controller/X.php', $source);
    }
}
