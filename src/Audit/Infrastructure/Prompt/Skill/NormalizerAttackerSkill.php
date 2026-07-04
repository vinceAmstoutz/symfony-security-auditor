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
final readonly class NormalizerAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::NORMALIZER;
    }

    #[Override]
    public function priority(): int
    {
        return 90;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="normalizer">
            Hunt:
            - `denormalize()` building an Entity from request payload with `'allow_extra_attributes' => true` (mass-assignment) or without `'attributes' => [...]` allowlist.
            - `denormalize()` calling private setters via reflection / `ObjectNormalizer` ignoring `#[Ignore]` on sensitive fields (`roles`, `passwordHash`, `isAdmin`).
            - `normalize()` leaking sensitive fields by default (no `groups`, no `ignored_attributes`) — API leaks password hashes, tokens, internal ids.
            - `supportsDenormalization()` returning `true` for `object` or untyped data — gadget-chain entry point.
            - Custom denormalizer using `unserialize()` to decode a transport field.
            - `getSupportedTypes()` returning `'*'` widely — denormalizer steals control from safer normalizers downstream.
            Do NOT flag:
            - `Symfony\Component\Serializer\Normalizer\PropertyNormalizer` without `setIgnoredAttributes()` when the model has only safe public properties.
            - Normalizers operating purely on read-only DTOs with no setters.
            </skills>
            SKILL;
    }
}
