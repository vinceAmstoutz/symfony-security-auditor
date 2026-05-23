<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

// INTENTIONALLY VULNERABLE — for demonstrating symfony-security-auditor.
// Do not deploy. Do not copy any of this into a real codebase.
final class UserController extends AbstractController
{
    // VULN: Direct Object Reference — no ownership check between the
    // authenticated user and the $id pulled straight from the URL.
    #[Route('/users/{id}', name: 'user_show', methods: ['GET'])]
    public function showAction(int $id, EntityManagerInterface $entityManager): JsonResponse
    {
        $user = $entityManager->getRepository(User::class)->find($id);
        if (null === $user) {
            return new JsonResponse(['error' => 'not found'], 404);
        }

        return new JsonResponse($user->toArray());
    }

    // VULN: Broken Access Control — DELETE endpoint with no #[IsGranted],
    // no denyAccessUnlessGranted(), and no Voter. Any authenticated user
    // can delete anyone.
    #[Route('/users/{id}', name: 'user_delete', methods: ['DELETE'])]
    public function deleteAction(int $id, EntityManagerInterface $entityManager): JsonResponse
    {
        $user = $entityManager->getRepository(User::class)->find($id);
        if (null === $user) {
            return new JsonResponse(['error' => 'not found'], 404);
        }

        $entityManager->remove($user);
        $entityManager->flush();

        return new JsonResponse(['deleted' => $id]);
    }

    #[Route('/users', name: 'user_create', methods: ['POST'])]
    public function createAction(Request $request, EntityManagerInterface $entityManager): JsonResponse
    {
        // VULN: mass assignment — see App\Entity\User::fromRequest.
        $payload = json_decode((string) $request->getContent(), true) ?? [];
        $user = User::fromRequest($payload);

        $entityManager->persist($user);
        $entityManager->flush();

        return new JsonResponse($user->toArray(), 201);
    }
}
