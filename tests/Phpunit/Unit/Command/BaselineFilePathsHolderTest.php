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

use PHPUnit\Framework\TestCase;
use Random\Engine\Xoshiro256StarStar;
use Random\Randomizer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EchoedFilePath;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineFilePathsHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command\Fixture\CountingFilePaths;

final class BaselineFilePathsHolderTest extends TestCase
{
    private const int GENERATED_CASES = 300;

    private const array GENERATED_PROJECTS = ['/abs/project', '/other/project', '/', 'C:\\abs\\project'];

    private const array GENERATED_FILES = ['src/A.php', 'src/B.php', 'lib/src/A.php'];

    public function test_it_names_no_file_before_a_run_hands_it_the_baseline(): void
    {
        self::assertSame([], (new BaselineFilePathsHolder())->naming('src/A.php'));
    }

    public function test_it_names_a_file_by_every_baseline_path_that_denotes_it_in_the_project_in_baseline_order(): void
    {
        $baselineFilePathsHolder = new BaselineFilePathsHolder();
        $baselineFilePathsHolder->set('/abs/project', [
            './src/A.php',
            'src/B.php',
            'src\A.php',
            '/elsewhere/src/A.php',
            '/abs/project/src/A.php',
            'lib/src/A.php',
            '/src/A.php',
            'src/A.php',
        ]);

        self::assertSame(
            [['./src/A.php', 'src\A.php', '/abs/project/src/A.php', '/src/A.php', 'src/A.php'], ['src/B.php']],
            [$baselineFilePathsHolder->naming('src/A.php'), $baselineFilePathsHolder->naming('src/B.php')],
        );
    }

    public function test_it_reads_the_baseline_once_however_many_files_it_names(): void
    {
        $countingFilePaths = new CountingFilePaths(['./src/A.php', 'src/B.php', '/abs/project/src/C.php']);
        $baselineFilePathsHolder = new BaselineFilePathsHolder();
        $baselineFilePathsHolder->set('/abs/project', $countingFilePaths);

        $namings = array_map($baselineFilePathsHolder->naming(...), ['src/A.php', 'src/B.php', 'src/C.php', 'src/D.php']);

        self::assertSame(
            [[['./src/A.php'], ['src/B.php'], ['/abs/project/src/C.php'], []], 3],
            [$namings, $countingFilePaths->readPaths],
        );
    }

    public function test_a_later_run_replaces_the_baseline_and_the_project_of_the_one_before(): void
    {
        $baselineFilePathsHolder = new BaselineFilePathsHolder();
        $baselineFilePathsHolder->set('/abs/project', ['./src/A.php', '/abs/project/src/A.php']);
        $baselineFilePathsHolder->set('/other/project', ['/abs/project/src/A.php', '/other/project/src/A.php']);

        self::assertSame(['/other/project/src/A.php'], $baselineFilePathsHolder->naming('src/A.php'));
    }

    public function test_it_names_each_file_by_the_baseline_paths_that_denote_it_as_a_walk_of_the_whole_baseline_does(): void
    {
        $randomizer = new Randomizer(new Xoshiro256StarStar(hash('sha256', 'baseline file paths', true)));

        for ($case = 0; $case < self::GENERATED_CASES; ++$case) {
            $projectPath = $this->generatedOf($randomizer, self::GENERATED_PROJECTS);
            $filePaths = $this->generatedFilePaths($randomizer);
            $baselineFilePathsHolder = new BaselineFilePathsHolder();
            $baselineFilePathsHolder->set($projectPath, $filePaths);

            foreach (self::GENERATED_FILES as $file) {
                self::assertSame(
                    $this->walkedNaming($filePaths, $file, $projectPath),
                    $baselineFilePathsHolder->naming($file),
                    \sprintf('generated case %d, %s in %s', $case, $file, $projectPath),
                );
            }
        }
    }

    /**
     * The paths a walk of the whole baseline names `$file` by, the way the
     * holder named a file before it indexed the baseline: each path, in the
     * baseline's order, whose comparable form is one of the file's.
     *
     * @param list<string> $filePaths
     *
     * @return list<string>
     */
    private function walkedNaming(array $filePaths, string $file, string $projectPath): array
    {
        $naming = [];
        foreach ($filePaths as $filePath) {
            if (\in_array(EchoedFilePath::comparable($filePath), EchoedFilePath::projectFileForms($file, $projectPath), true)) {
                $naming[] = $filePath;
            }
        }

        return $naming;
    }

    /**
     * Up to a dozen paths, each a spelling of a generated file as a baseline
     * may hold it: as written, with a leading `./`, `/` or `.\`, on
     * backslashes, or absolute in one of the generated projects.
     *
     * @return list<string>
     */
    private function generatedFilePaths(Randomizer $randomizer): array
    {
        $filePaths = [];
        for ($index = $randomizer->getInt(0, 12); $index > 0; --$index) {
            $file = $this->generatedOf($randomizer, self::GENERATED_FILES);
            $filePaths[] = $this->generatedOf($randomizer, [
                $file,
                './'.$file,
                '/'.$file,
                '.\\'.str_replace('/', '\\', $file),
                str_replace('/', '\\', $file),
                \sprintf('%s/%s', $this->generatedOf($randomizer, self::GENERATED_PROJECTS), $file),
            ]);
        }

        return $filePaths;
    }

    /**
     * @param non-empty-list<string> $values
     */
    private function generatedOf(Randomizer $randomizer, array $values): string
    {
        return $values[$randomizer->getInt(0, \count($values) - 1)];
    }
}
