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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bridge\Fixture;

use Override;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Lets another run put its unpacked Composer in place just before this one
 * renames its own there.
 */
final class RaceLosingFilesystem extends Filesystem
{
    #[Override]
    public function rename(string $origin, string $target, bool $overwrite = false): void
    {
        $this->mkdir(\sprintf('%s/bin', $target));
        file_put_contents(\sprintf('%s/bin/composer', $target), '<?php // unpacked by another run');

        parent::rename($origin, $target, $overwrite);
    }
}
