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
final readonly class TwigExtensionAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::TWIG_EXTENSION;
    }

    #[Override]
    public function priority(): int
    {
        return 145;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="twig_extension">
            Twig extensions register functions and filters callable from every template in the project — a single unsafe one is reachable wherever a template author (or, on a CMS with editable templates, an end user) can call it. Hunt:
            - Custom functions/filters that shell out, read/write files, or build a path from a template-supplied argument (`getFunctions()`/`getFilters()` callables wrapping `file_get_contents`, `include`, `Process`, `fopen`) — RCE/LFI if templates are ever user-editable.
            - Functions/filters returning raw HTML (string concatenation, `sprintf` into markup) without declaring `is_safe: ['html']` deliberately and sanitizing the input first — Twig will double-escape a safely-marked filter's output, so an author who marks `is_safe` to silence that behavior on unsanitized user content produces stored/reflected XSS.
            - Authorization-sensitive lookups inside a function/filter (loading an entity, resolving a user, computing a price) with no call to the security context (`Security::isGranted()`/`AuthorizationCheckerInterface`) — an IDOR reachable from any template that calls it, bypassing the controller's checks entirely.
            - `getGlobals()` entries exposing configuration values, API keys, or full user/security objects to every template's scope — broader exposure than the template author asked for.
            - Filters/functions accepting a class name or callable string from a template variable and invoking it dynamically — template-controlled instantiation.
            Do NOT flag:
            - Pure formatting functions/filters (dates, numbers, currency, string case) with no file, network, or database access.
            - `is_safe: ['html']` on output built exclusively from hardcoded markup or from values already passed through an `HtmlSanitizerInterface`.
            - Globals exposing non-sensitive, already-public configuration (site name, locale, feature flags with no security implication).
            </skills>
            SKILL;
    }
}
