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
final readonly class FileUploadAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::FORM;
    }

    #[Override]
    public function priority(): int
    {
        return 115;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="file_upload">
            Hunt (`FileType` fields, `VichUploaderBundle` mappings, and manual `UploadedFile` handling):
            - Extension/MIME validation missing or based on the client-supplied `Content-Type` header / `getClientMimeType()` instead of `guessExtension()` or a server-side allow-list.
            - No `maxSize` constraint (or a `MimeType`/`File` constraint with an empty `mimeTypes` allow-list), letting an attacker exhaust disk space.
            - Stored filename built from `getClientOriginalName()` without sanitization — user-controlled `../../etc/passwd`-style path traversal into `move()`'s target directory.
            - Upload target directory inside the public web root (`public/uploads`, `public/media`) without a `.htaccess` / web-server rule disabling script execution — an uploaded `.php`/`.phtml`/`.phar` becomes remote code execution.
            - Stored filename derived from the original name or a predictable counter/timestamp instead of a random token (`uniqid()` without the `more_entropy` argument, sequential IDs) — enables overwrite of another user's file or enumeration of private uploads.
            - Upload controller/form action reachable without `denyAccessUnlessGranted()` / `#[IsGranted]` where the surrounding feature requires authentication.
            - A download/serve route for uploaded files that streams by filename or ID without re-checking the requester's access to the owning entity.
            Do NOT flag:
            - Handlers validating the extension against an explicit allow-list (`mimeTypes: ['image/png', 'image/jpeg']` or an equivalent `in_array()` check) AND storing outside the public web root, or with execution disabled for that path.
            - Filenames generated via `uniqid('', true)`, `Uuid::v4()`, `md5(uniqid())`, or `VichUploaderBundle`'s default namer — these are unpredictable enough to resist enumeration.
            - Download actions that resolve the owning entity first and call `denyAccessUnlessGranted()` against it before streaming the file.
            </skills>
            SKILL;
    }
}
