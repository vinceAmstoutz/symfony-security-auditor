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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;

final class RegexCodeSlicerTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_files_shorter_than_threshold_are_returned_unchanged(): void
    {
        $content = "<?php\nclass Tiny { public function foo() { return 1; } }";
        $projectFile = ProjectFile::create('src/Tiny.php', '/app/src/Tiny.php', $content);

        self::assertSame($content, (new RegexCodeSlicer(80))->slice($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_non_php_files_are_returned_unchanged(): void
    {
        $content = str_repeat("{{ value }}\n", 100);
        $projectFile = ProjectFile::create('templates/x.html.twig', '/app/templates/x.html.twig', $content);

        self::assertSame($content, (new RegexCodeSlicer(10))->slice($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
    public function test_file_one_line_below_threshold_is_not_sliced(): void
    {
        $lines = array_fill(0, 8, '        $inert = 1;');
        array_unshift($lines, '<?php');
        $content = implode("\n", $lines); // 9 lines
        $projectFile = ProjectFile::create('src/Below.php', '/app/src/Below.php', $content);

        self::assertSame($content, (new RegexCodeSlicer(10))->slice($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_slicing_preserves_total_line_count(): void
    {
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeController());

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertSame(
            substr_count($projectFile->content(), "\n"),
            substr_count($sliced, "\n"),
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_lines_with_security_tokens_are_retained(): void
    {
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeController());

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString("\$request->get('payload')", $sliced);
        self::assertStringContainsString('unserialize($payload)', $sliced);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_inert_body_lines_are_elided(): void
    {
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeController());

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringNotContainsString('INERT_MARKER', $sliced);
        self::assertStringContainsString('// elided', $sliced);
    }

    /**
     * @throws InvalidProjectFileException
     */
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
        yield 'method signature with no visibility modifier' => ['function delete(Request $request, string $id): Response'];
        yield 'static method signature with no visibility modifier' => ['static function fromRequest(Request $request): self'];
        yield 'static property with no visibility modifier' => ['static $instance;'];
        yield 'enum case' => ["case ROLE_ADMIN = 'ROLE_ADMIN';"];
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_indented_structural_line_is_retained(): void
    {
        // Pins the ltrim() call: the method signature is indented, so detection
        // must trim leading whitespace before matching the `public ` prefix.
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20)."        public function deeplyIndented(): void\n".str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString('public function deeplyIndented(): void', $sliced);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_multiline_method_signature_parameters_are_retained(): void
    {
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20)
            ."    public function import(\n"
            ."        Request \$request,\n"
            ."        AdminOnlyDataMapper \$dataMapper\n"
            ."    ): Response\n"
            ."    {\n"
            .str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString('Request $request,', $sliced);
        self::assertStringContainsString('AdminOnlyDataMapper $dataMapper', $sliced);
        self::assertStringContainsString('): Response', $sliced);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_closing_paren_inside_a_string_literal_default_value_does_not_break_continuation_tracking(): void
    {
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20)
            ."    public function process(\n"
            ."        string \$label = 'Confirm)',\n"
            ."        AdminOnlyDataMapper \$dataMapper,\n"
            ."        int \$retries = 3,\n"
            ."    ): void {\n"
            .str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString('AdminOnlyDataMapper $dataMapper,', $sliced);
        self::assertStringContainsString('int $retries = 3,', $sliced);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_line_after_a_closed_multiline_signature_is_still_elided(): void
    {
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20)
            ."    public function import(\n"
            ."        Request \$request\n"
            ."    ): Response\n"
            ."    {\n"
            ."        \$inert = 'INERT_MARKER';\n"
            .str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringNotContainsString('INERT_MARKER', $sliced);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_multi_line_string_literal_with_an_unbalanced_paren_does_not_defeat_elision_for_the_rest_of_the_file(): void
    {
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20)
            ."    public function process(\n"
            ."        string \$default = \"opening paren example (\n"
            ."        unbalanced\"\n"
            ."    ) {\n"
            ."        \$inert = 'INERT_MARKER';\n"
            .str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringNotContainsString('INERT_MARKER', $sliced);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_string_literal_spanning_three_lines_does_not_defeat_elision_for_the_rest_of_the_file(): void
    {
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20)
            ."    public function process(\n"
            ."        string \$default = \"opening line (\n"
            ."        middle line with parens ( and ) but no quote\n"
            ."        closing line\"\n"
            ."    ) {\n"
            ."        \$inert = 'INERT_MARKER';\n"
            .str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringNotContainsString('INERT_MARKER', $sliced);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_inert_line_resembling_keyword_mid_line_is_elided(): void
    {
        // A comment mentioning "namespace"/"class" mid-line must NOT be treated as
        // structural — it is only structural when the keyword is at the line start.
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20)."        // the class and namespace are fine\n".str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringNotContainsString('the class and namespace are fine', $sliced);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_bare_include_and_require_statements_are_retained(): void
    {
        $projectFile = ProjectFile::create('src/Controller/PageController.php', '/app/src/Controller/PageController.php', $this->largeControllerWithBareIncludes());

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString('include $partial;', $sliced);
        self::assertStringContainsString('require_once $bootstrap;', $sliced);
    }

    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('parenthesizedInclusionCases')]
    public function test_parenthesized_inclusion_calls_are_retained(string $inclusionLine): void
    {
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20).\sprintf('        %s%s', $inclusionLine, \PHP_EOL).str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString($inclusionLine, $sliced);
    }

    /** @return iterable<string, array{string}> */
    public static function parenthesizedInclusionCases(): iterable
    {
        yield 'include' => ['include($partial);'];
        yield 'include_once' => ['include_once($partial);'];
        yield 'require' => ['require($bootstrap);'];
        yield 'require_once' => ['require_once($bootstrap);'];
    }

    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('unanchoredSecurityKeywordCases')]
    public function test_column_zero_and_tab_indented_security_keywords_are_retained(string $keywordLine): void
    {
        $content = "<?php\n".str_repeat("        \$x = 1;\n", 20).$keywordLine."\n".str_repeat("        \$x = 1;\n", 20);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($projectFile);

        self::assertStringContainsString($keywordLine, $sliced);
    }

    /** @return iterable<string, array{string}> */
    public static function unanchoredSecurityKeywordCases(): iterable
    {
        yield 'column-zero exec call' => ['exec($userInput);'];
        yield 'column-zero rand call' => ['rand();'];
        yield 'column-zero include statement' => ['include $partial;'];
        yield 'column-zero include_once call' => ['include_once($partial);'];
        yield 'column-zero require statement' => ['require $bootstrap;'];
        yield 'column-zero require_once call' => ['require_once($bootstrap);'];
        yield 'tab-indented require statement' => ["\trequire \$bootstrap;"];
        yield 'tab-indented exec call' => ["\texec(\$cmd);"];
    }

    private function largeControllerWithBareIncludes(): string
    {
        $inert = str_repeat("        \$x = INERT_MARKER;\n", 25);

        return <<<PHP
            <?php

            namespace App\\Controller;

            use Symfony\\Component\\HttpFoundation\\Response;

            class PageController
            {
                public function render(string \$partial): Response
                {
                    include \$partial;

                    return new Response('ok');
                }

                public function bootstrap(string \$bootstrap): Response
                {
                    require_once \$bootstrap;
            {$inert}
                    return new Response('ok');
                }
            }
            PHP;
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
