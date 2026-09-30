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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Review;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\CodeContextResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

final class CodeContextResolverTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_resolves_the_content_of_the_scanned_file_a_finding_names(): void
    {
        self::assertSame('<?php // b', CodeContextResolver::resolve('src/B.php', $this->projectFiles()));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_resolves_a_path_the_attacker_echoed_with_a_leading_dot_slash(): void
    {
        self::assertSame('<?php // b', CodeContextResolver::resolve('./src/B.php', $this->projectFiles()));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_resolves_nothing_for_a_file_outside_the_scanned_set(): void
    {
        self::assertSame('', CodeContextResolver::resolve('src/C.php', $this->projectFiles()));
    }

    /**
     * @return list<ProjectFile>
     *
     * @throws InvalidProjectFileException
     */
    private function projectFiles(): array
    {
        return [
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php // a'),
            ProjectFile::create('src/B.php', '/app/src/B.php', '<?php // b'),
        ];
    }
}
