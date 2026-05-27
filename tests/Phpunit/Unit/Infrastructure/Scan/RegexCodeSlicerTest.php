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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;

final class RegexCodeSlicerTest extends TestCase
{
    public function test_files_shorter_than_threshold_are_returned_unchanged(): void
    {
        $content = "<?php\nclass Tiny { public function foo() { return 1; } }";
        $projectFile = ProjectFile::create('src/Tiny.php', '/app/src/Tiny.php', $content);

        self::assertSame($content, (new RegexCodeSlicer(80))->slice($projectFile));
    }

    public function test_non_php_files_are_returned_unchanged(): void
    {
        $content = str_repeat("{{ value }}\n", 100);
        $projectFile = ProjectFile::create('templates/x.html.twig', '/app/templates/x.html.twig', $content);

        self::assertSame($content, (new RegexCodeSlicer(10))->slice($projectFile));
    }

    public function test_file_at_exactly_the_threshold_is_sliced(): void
    {
        // Pins GreaterThanOrEqualTo (>=) against GreaterThan (>): a file whose line
        // count equals the threshold must be sliced, so its inert line is elided.
        $lines = array_fill(0, 9, '        $inert = 1;');
        array_unshift($lines, '<?php');
        $content = implode("\n", $lines); // exactly 10 lines
        $projectFile = ProjectFile::create('src/Exact.php', '/app/src/Exact.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString('// elided', $sliced);
    }

    public function test_file_one_line_below_threshold_is_not_sliced(): void
    {
        $lines = array_fill(0, 8, '        $inert = 1;');
        array_unshift($lines, '<?php');
        $content = implode("\n", $lines); // 9 lines
        $projectFile = ProjectFile::create('src/Below.php', '/app/src/Below.php', $content);

        self::assertSame($content, (new RegexCodeSlicer(10))->slice($projectFile));
    }

    public function test_slicing_preserves_total_line_count(): void
    {
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeController());

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertSame(
            substr_count($projectFile->content(), "\n"),
            substr_count($sliced, "\n"),
        );
    }

    public function test_lines_with_security_tokens_are_retained(): void
    {
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeController());

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString("\$request->get('payload')", $sliced);
        self::assertStringContainsString('unserialize($payload)', $sliced);
    }

    public function test_inert_body_lines_are_elided(): void
    {
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeController());

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringNotContainsString('INERT_MARKER', $sliced);
        self::assertStringContainsString('// elided', $sliced);
    }

    #[DataProvider('structuralLineCases')]
    public function test_structural_lines_are_retained(string $structuralLine): void
    {
        $content = "<?php\n".str_repeat("        \$inert = 1;\n", 20).$structuralLine."\n".str_repeat("        \$inert = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString($structuralLine, $sliced);
    }

    /** @return iterable<string, array{string}> */
    public static function structuralLineCases(): iterable
    {
        yield 'namespace' => ['namespace App\\Controller;'];
        yield 'use' => ['use Symfony\\Component\\HttpFoundation\\Request;'];
        yield 'attribute' => ["#[Route('/users')]"];
        yield 'class declaration' => ['class UserController'];
        yield 'final class declaration' => ['final class WidgetController'];
        yield 'interface declaration' => ['interface Foo'];
        yield 'trait declaration' => ['trait Bar'];
        yield 'enum declaration' => ['enum Status: string'];
        yield 'abstract declaration' => ['abstract class Base'];
        yield 'readonly declaration' => ['readonly class Value'];
        yield 'public method signature' => ['public function show(): void'];
        yield 'protected member' => ['protected string $name;'];
        yield 'private member' => ['private int $count = 0;'];
    }

    public function test_indented_structural_line_is_retained(): void
    {
        // Pins the ltrim() call: the method signature is indented, so detection
        // must trim leading whitespace before matching the `public ` prefix.
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20)."        public function deeplyIndented(): void\n".str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString('public function deeplyIndented(): void', $sliced);
    }

    public function test_inert_line_resembling_keyword_mid_line_is_elided(): void
    {
        // A comment mentioning "namespace"/"class" mid-line must NOT be treated as
        // structural — it is only structural when the keyword is at the line start.
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20)."        // the class and namespace are fine\n".str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringNotContainsString('the class and namespace are fine', $sliced);
    }

    private function largeController(): string
    {
        $inert = str_repeat("        \$x = INERT_MARKER;\n", 25);

        return <<<PHP
            <?php

            namespace App\\Controller;

            use Symfony\\Component\\HttpFoundation\\Request;
            use Symfony\\Component\\HttpFoundation\\Response;

            class UserController
            {
                public function hot(Request \$request): Response
                {
                    \$payload = \$request->get('payload');
                    \$data = unserialize(\$payload);

                    return new Response((string) \$data);
                }

                public function cold(): Response
                {
            {$inert}
                    return new Response('ok');
                }
            }
            PHP;
    }
}
