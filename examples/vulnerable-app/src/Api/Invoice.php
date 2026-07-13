<?php

declare(strict_types=1);

namespace App\Api;

use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;

// INTENTIONALLY VULNERABLE — for demonstrating symfony-security-auditor.
// Do not deploy. Do not copy any of this into a real codebase.

// VULN: over-permissive serializer group / broken object-level authorization —
// the resource exposes a collection endpoint with no `security` attribute and
// serializes every property, including the internal `costPrice` and the owning
// customer's identifier, to any caller. A real fix scopes a normalization group
// to the public fields and adds `security: "is_granted('VIEW', object)"`.
#[ApiResource(
    operations: [
        new Get(),
        new GetCollection(),
    ],
)]
final class Invoice
{
    public int $id = 0;

    public string $reference = '';

    public int $amountDue = 0;

    public int $costPrice = 0;

    public int $customerId = 0;
}
