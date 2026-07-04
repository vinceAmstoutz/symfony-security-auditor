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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

use Symfony\Component\Filesystem\Filesystem;

use function Symfony\Component\String\u;

/** @internal loads the console/HTML report templates from the Template directory */
final readonly class TemplateLoader
{
    private const string TEMPLATE_DIRECTORY_NAME = 'Template';

    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    public function load(string $name): string
    {
        return u($this->filesystem->readFile(\sprintf('%s/%s/%s', __DIR__, self::TEMPLATE_DIRECTORY_NAME, $name)))->trimEnd("\n")->toString();
    }
}
