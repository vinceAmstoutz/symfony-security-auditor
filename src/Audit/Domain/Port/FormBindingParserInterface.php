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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Extracts FormType bindings — `$this->createForm(SomeFormType::class, ...)`
 * call sites — from a controller file. One `FormBinding` is emitted per call
 * site so the same controller method may produce multiple entries when it
 * builds several forms. Implementations must degrade silently (return empty
 * list) when the file cannot be parsed.
 */
interface FormBindingParserInterface
{
    /**
     * @return list<FormBinding>
     */
    public function parse(ProjectFile $projectFile): array;
}
