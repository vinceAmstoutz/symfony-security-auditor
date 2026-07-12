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
final readonly class ControllerFileUploadAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::CONTROLLER;
    }

    #[Override]
    public function priority(): int
    {
        return 15;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="file_upload_controller">
            Hunt (manual `UploadedFile` handling — no Symfony `FormType` involved, e.g. `$request->files->get()` on an API-style upload endpoint):
            - Extension/MIME validation missing, or based on the client-supplied `Content-Type` / `getClientMimeType()` instead of `guessExtension()` or a server-side allow-list.
            - No size limit enforced before or during `move()`, letting an attacker exhaust disk space.
            - Stored path built from `getClientOriginalName()` without sanitization — user-controlled `../../etc/passwd`-style path traversal into `move()`'s target directory.
            - Upload target directory inside the public web root (`public/uploads`, `public/media`) without a `.htaccess` / web-server rule disabling script execution — an uploaded `.php`/`.phtml`/`.phar` becomes remote code execution.
            - Stored filename derived from the original name or a predictable counter/timestamp instead of a random token — enables overwrite of another user's file or enumeration of private uploads.
            - Upload or download actions reachable without `denyAccessUnlessGranted()` / `#[IsGranted]` where the surrounding feature requires authentication.
            - A download/serve action that streams a file by filename or ID without re-checking the requester's access to the owning entity or record.
            Do NOT flag:
            - Handlers validating the extension against an explicit allow-list AND storing outside the public web root, or with execution disabled for that path.
            - Filenames generated via `uniqid('', true)`, `Uuid::v4()`, `md5(uniqid())`, or an equivalent unpredictable token.
            - Download actions that resolve the owning entity first and call `denyAccessUnlessGranted()` against it before streaming the file.
            </skills>
            SKILL;
    }
}
