<?php

declare(strict_types=1);

namespace App\Twig\Components;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\UX\LiveComponent\Attribute\AsLiveComponent;
use Symfony\UX\LiveComponent\Attribute\LiveAction;
use Symfony\UX\LiveComponent\Attribute\LiveProp;

// INTENTIONALLY VULNERABLE — for demonstrating symfony-security-auditor.
// Do not deploy. Do not copy any of this into a real codebase.
#[AsLiveComponent]
final class UserCard
{
    #[LiveProp(writable: true)]
    public int $userId = 0;

    public function __construct(private readonly EntityManagerInterface $entityManager) {}

    // VULN: unauthenticated live action / broken access control — `#[LiveAction]`
    // methods are HTTP endpoints, yet this one promotes any user to admin with no
    // `#[IsGranted]` check and trusts the client-writable `$userId` LiveProp. Any
    // visitor can POST the component action and escalate privileges. A real fix
    // guards the action with `#[IsGranted('ROLE_ADMIN')]` and never derives the
    // target from a writable prop.
    #[LiveAction]
    public function promote(): void
    {
        $user = $this->entityManager->getRepository(User::class)->find($this->userId);
        $user->roles[] = 'ROLE_ADMIN';
        $this->entityManager->flush();
    }
}
