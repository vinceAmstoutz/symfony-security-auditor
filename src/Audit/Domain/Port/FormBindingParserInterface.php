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
 * Extracts one `FormBinding` per `$this->createForm(SomeFormType::class, ...)`
 * call site of a controller file. Implementations MUST return an empty list
 * for a file they cannot parse.
 */
interface FormBindingParserInterface
{
    /**
     * @return list<FormBinding>
     */
    public function parse(ProjectFile $projectFile): array;
}
