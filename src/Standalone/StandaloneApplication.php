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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use Override;
use Symfony\Component\Console\Application;

/**
 * Extends the bare Symfony `Application` only to append the bundled
 * `symfony/models-dev` pricing-catalog version to `--version` — the base
 * class offers no other extension point for this.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class StandaloneApplication extends Application
{
    public function __construct(
        string $name,
        string $version,
        private readonly string $modelsDevVersion,
    ) {
        parent::__construct($name, $version);
    }

    #[Override]
    public function getLongVersion(): string
    {
        return \sprintf('%s (symfony/models-dev %s)', parent::getLongVersion(), $this->modelsDevVersion);
    }
}
