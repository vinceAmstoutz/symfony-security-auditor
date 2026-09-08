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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Model;

final readonly class FormBinding
{
    public function __construct(
        private string $entrypointFilePath,
        private string $controllerMethod,
        private string $formTypeClass,
    ) {}

    public function entrypointFilePath(): string
    {
        return $this->entrypointFilePath;
    }

    public function controllerMethod(): string
    {
        return $this->controllerMethod;
    }

    public function formTypeClass(): string
    {
        return $this->formTypeClass;
    }
}
