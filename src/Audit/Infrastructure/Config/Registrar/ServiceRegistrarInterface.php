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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Registrar;

use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;

/**
 * One slice of the audit object graph. A new conditional wiring concern is a
 * new implementation listed in the composition root, not another branch in it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ServiceRegistrarInterface
{
    public function register(ServicesConfigurator $servicesConfigurator, BundleConfiguration $bundleConfiguration): void;
}
