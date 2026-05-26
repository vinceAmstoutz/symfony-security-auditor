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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexCodeSlicer;

final class RegexCodeSlicerTest extends TestCase
{
    public function test_files_shorter_than_threshold_are_returned_unchanged(): void
    {
        $content = "<?php\nclass Tiny { public function foo() { return 1; } }";
        $file = ProjectFile::create('src/Tiny.php', '/app/src/Tiny.php', $content);

        $sliced = (new RegexCodeSlicer(80))->slice($file);

        self::assertSame($content, $sliced);
    }

    public function test_non_php_files_are_returned_unchanged(): void
    {
        $content = str_repeat("{{ value }}\n", 100);
        $file = ProjectFile::create('templates/x.html.twig', '/app/templates/x.html.twig', $content);

        $sliced = (new RegexCodeSlicer(10))->slice($file);

        self::assertSame($content, $sliced);
    }

    public function test_sliced_output_preserves_line_count(): void
    {
        $file = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeControllerContent());

        $sliced = (new RegexCodeSlicer(10))->slice($file);

        self::assertSame(
            substr_count($file->content(), "\n"),
            substr_count($sliced, "\n"),
        );
    }

    public function test_hot_method_bodies_are_retained_in_full(): void
    {
        $file = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeControllerContent());

        $sliced = (new RegexCodeSlicer(10))->slice($file);

        self::assertStringContainsString('$request->get(', $sliced);
        self::assertStringContainsString('unserialize($payload)', $sliced);
    }

    public function test_cold_method_bodies_are_replaced_with_elided_placeholder(): void
    {
        $file = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeControllerContent());

        $sliced = (new RegexCodeSlicer(10))->slice($file);

        self::assertStringNotContainsString('COLD_BODY_MARKER', $sliced);
        self::assertStringContainsString('// elided', $sliced);
    }

    public function test_cold_method_signatures_are_retained(): void
    {
        $file = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeControllerContent());

        $sliced = (new RegexCodeSlicer(10))->slice($file);

        self::assertStringContainsString('public function cold(', $sliced);
    }

    public function test_namespace_and_use_lines_are_retained(): void
    {
        $file = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeControllerContent());

        $sliced = (new RegexCodeSlicer(10))->slice($file);

        self::assertStringContainsString('namespace App\\Controller;', $sliced);
        self::assertStringContainsString('use Symfony\\Component\\HttpFoundation\\Request;', $sliced);
    }

    public function test_class_signature_and_php_attributes_are_retained(): void
    {
        $file = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeControllerContent());

        $sliced = (new RegexCodeSlicer(10))->slice($file);

        self::assertStringContainsString('#[Route(\'/users\')]', $sliced);
        self::assertStringContainsString('class UserController', $sliced);
    }

    public function test_sliced_output_is_strictly_smaller_than_input_when_cold_methods_exist(): void
    {
        $file = ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', $this->largeControllerContent());

        $sliced = (new RegexCodeSlicer(10))->slice($file);

        self::assertLessThan(\strlen($file->content()), \strlen($sliced));
    }

    private function largeControllerContent(): string
    {
        $coldBody = str_repeat("        \$x = COLD_BODY_MARKER; // line N\n", 30);

        return <<<PHP
            <?php

            namespace App\\Controller;

            use Symfony\\Component\\HttpFoundation\\Request;
            use Symfony\\Component\\HttpFoundation\\Response;
            use Symfony\\Component\\Routing\\Annotation\\Route;

            #[Route('/users')]
            class UserController
            {
                public function hot(Request \$request): Response
                {
                    \$payload = \$request->get('payload');
                    \$data = unserialize(\$payload);

                    return new Response(json_encode(\$data));
                }

                public function cold(): Response
                {
            $coldBody
                    return new Response('ok');
                }
            }
            PHP;
    }
}
