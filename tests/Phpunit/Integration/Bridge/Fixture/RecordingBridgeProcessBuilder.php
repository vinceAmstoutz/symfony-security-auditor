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

use Symfony\Component\Process\Process;

final class RecordingBridgeProcessBuilder
{
    private string $package = '';

    public function __invoke(string $package): Process
    {
        $this->package = $package;

        return new Process(['true']);
    }

    public function package(): string
    {
        return $this->package;
    }
}
