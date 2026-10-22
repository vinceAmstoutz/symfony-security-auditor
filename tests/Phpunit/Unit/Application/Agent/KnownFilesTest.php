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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\KnownFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

final class KnownFilesTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('spellingsOfAFileOnlyTheLaterFilesHold')]
    public function test_a_path_naming_only_a_file_the_later_known_files_hold_is_named_by_it(string $echoedPath): void
    {
        $knownFiles = new KnownFiles([$this->file('src/A.php')], new KnownFiles([$this->file('src/A.php'), $this->file('src/B.php')]));

        self::assertSame('src/B.php', $knownFiles->name($echoedPath));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function spellingsOfAFileOnlyTheLaterFilesHold(): iterable
    {
        yield 'as the project names it' => ['src/B.php'];
        yield 'as an absolute path' => ['/app/src/B.php'];
        yield 'with a leading dot slash' => ['./src/B.php'];
        yield 'with backslashes' => ['src\\B.php'];
    }

    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('spellingsOfAFileBothHold')]
    public function test_a_file_the_earlier_and_the_later_known_files_both_hold_names_a_path_alone(string $echoedPath): void
    {
        $knownFiles = new KnownFiles([$this->file('src/A.php')], new KnownFiles([$this->file('src/B.php'), $this->file('src/A.php')]));

        self::assertSame('src/A.php', $knownFiles->name($echoedPath));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function spellingsOfAFileBothHold(): iterable
    {
        yield 'with a leading dot slash' => ['./src/A.php'];
        yield 'with backslashes' => ['src\\A.php'];
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_path_named_as_written_by_an_earlier_file_and_a_later_one_is_named_by_the_earlier_file(): void
    {
        $knownFiles = new KnownFiles([$this->file('lib/B.php', '/app/src/B.php')], new KnownFiles([$this->file('src/B.php')]));

        self::assertSame('lib/B.php', $knownFiles->name('/app/src/B.php'));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_path_a_later_file_names_as_written_is_named_by_it_though_its_folded_form_denotes_two_files(): void
    {
        $knownFiles = new KnownFiles([$this->file('src/A.php')], new KnownFiles([$this->file('src/Service\\Pay.php'), $this->file('src/Service/Pay.php')]));

        self::assertSame('src/Service\\Pay.php', $knownFiles->name('/app/src/Service\\Pay.php'));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_path_two_files_name_as_written_is_named_by_the_first_of_them(): void
    {
        $knownFiles = new KnownFiles([$this->file('lib/B.php', '/app/src/B.php'), $this->file('src/B.php')]);

        self::assertSame('lib/B.php', $knownFiles->name('/app/src/B.php'));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_folded_spelling_denoting_an_earlier_file_and_another_later_one_stays_as_written(): void
    {
        $knownFiles = new KnownFiles([$this->file('src/Service\\Pay.php')], new KnownFiles([$this->file('src/Service/Pay.php')]));

        self::assertSame('./src/Service/Pay.php', $knownFiles->name('./src/Service/Pay.php'));
    }

    public function test_without_known_files_a_path_stays_as_written(): void
    {
        self::assertSame('./src/A.php', (new KnownFiles())->name('./src/A.php'));
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function file(string $relativePath, ?string $absolutePath = null): ProjectFile
    {
        return ProjectFile::create($relativePath, $absolutePath ?? \sprintf('/app/%s', $relativePath), '<?php');
    }
}
