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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class FormAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::FORM;
    }

    #[Override]
    public function priority(): int
    {
        return 110;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="form">
            Hunt:
            - `'csrf_protection' => false` on forms processing state changes (acceptable only for stateless APIs with their own auth).
            - `'allow_extra_fields' => true` enabling mass assignment of unmapped properties via setters.
            - `EntityType` choice queries unscoped by ownership — attacker can select any other tenant's row.
            - Data transformers that `unserialize` / `json_decode` raw input without strict mode.
            - Missing `'constraints'` on free-form fields that flow into the database or shell.
            Do NOT flag:
            - Forms with the default CSRF token (Symfony enables it by default — only explicit `false` is the smell).
            - Fields declared `mapped: false` and re-validated by a constraint — those don't reach the entity setter.
            </skills>
            SKILL;
    }
}
