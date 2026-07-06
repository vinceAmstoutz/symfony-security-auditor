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
final readonly class EntityFileUploadAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::ENTITY;
    }

    #[Override]
    public function priority(): int
    {
        return 135;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="file_upload_entity">
            Hunt (`VichUploaderBundle` mappings and other entity-level file storage):
            - `#[Vich\UploadableField]` (or `@Vich\UploadableField`) with no `namer` configured, or a `namer` built from the original filename — predictable, overwritable storage paths.
            - A `File`/`UploadedFile`-typed property with no `#[Assert\File]` (or equivalent) MIME/size constraint applied to it.
            - The stored file path or filename exposed through a `#[Groups([...])]` read group reachable by unauthorized users, letting them guess or directly access another user's file.
            - A Vich `uploadDestination` / `uriPrefix` under the public web root without disabling script execution for that path.
            - A file-replacement flow (re-uploading over an existing mapped field) that doesn't re-check ownership before the previous file is overwritten or deleted.
            Do NOT flag:
            - `Vich\UploadableField` using its default namer, or an explicit `Uuid`/hash-based namer — unpredictable enough to resist enumeration.
            - `#[Assert\File]` present with an explicit `mimeTypes` allow-list and `maxSize`.
            - Read groups exposing a path that is meant to be publicly reachable (e.g. a public avatar), where nothing sensitive is at stake.
            </skills>
            SKILL;
    }
}
