<?php

declare(strict_types=1);

namespace App\Controller;

use Doctrine\DBAL\Connection;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

// INTENTIONALLY VULNERABLE — for demonstrating symfony-security-auditor.
// Do not deploy. Do not copy any of this into a real codebase.
final class SearchController extends AbstractController
{
    public function __construct(private readonly Connection $connection) {}

    // VULN: SQL injection — request input concatenated directly into the
    // query. A real fix uses a parameterized query (executeQuery + bound
    // params) or the QueryBuilder's setParameter().
    #[Route('/search', name: 'search_query', methods: ['GET'])]
    public function queryAction(Request $request): JsonResponse
    {
        $term = (string) $request->query->get('q', '');
        $sql = "SELECT id, name FROM users WHERE name LIKE '%".$term."%' ORDER BY id";

        $rows = $this->connection->fetchAllAssociative($sql);

        return new JsonResponse(['results' => $rows]);
    }
}
