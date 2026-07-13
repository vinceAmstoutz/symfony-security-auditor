<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

// INTENTIONALLY VULNERABLE — for demonstrating symfony-security-auditor.
// Do not deploy. Do not copy any of this into a real codebase.
final class AvatarUploadController extends AbstractController
{
    // VULN: unrestricted file upload — the client-supplied original filename
    // is trusted for both the extension check and the destination path, so an
    // attacker uploads `avatar.php` (or `../../public/shell.php`) and the file
    // lands under the web root, executable. A real fix validates the MIME type
    // server-side, generates a random basename, and stores outside the docroot.
    #[Route('/account/avatar', name: 'avatar_upload', methods: ['POST'])]
    public function uploadAction(Request $request): JsonResponse
    {
        $file = $request->files->get('avatar');
        $name = $file->getClientOriginalName();

        $file->move($this->getParameter('kernel.project_dir').'/public/uploads', $name);

        return new JsonResponse(['stored' => '/uploads/'.$name]);
    }
}
