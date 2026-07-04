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
final readonly class TemplateAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::TEMPLATE;
    }

    #[Override]
    public function priority(): int
    {
        return 140;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="template">
            Hunt:
            - `|raw` filter applied to variables originating from user input or untrusted DB content.
            - `autoescape` overridden to `false` or to a context that does not match the surrounding HTML/JS/URL context.
            - `{{ include(user_input) }}` or `{% include %}` with dynamic template names — SSTI vector.
            - `{% sandbox %}` / `{% apply %}` blocks lifting restrictions on user-supplied template fragments.
            - Inline JavaScript context (`<script>var x = {{ value }};`) without `|json_encode` — XSS via Twig.
            - URL attributes (`href`, `src`) built from user input without `|url_encode` and protocol whitelist (javascript:, data:).
            - Twig Components (`<twig:Component …/>`) passing user input through `data-*` attributes without escaping (`<twig:UserCard name="{{ name|raw }}"/>`).
            - Live Components emitting `data-live-action-param` / `data-live-prop` with untrusted values — bound back to the server unchecked.
            Do NOT flag:
            - Default `{{ value }}` interpolation — Twig auto-escapes for the active context.
            - `|raw` on values originating from a `Markdown` / `Sanitize` (HtmlSanitizer) transformation upstream — trust the sanitizer unless evidence shows otherwise.
            - `{% component %}` / `<twig:…/>` with statically-typed props in a `LiveComponent` whose writable props are constrained by validators.
            </skills>
            SKILL;
    }
}
