<?php

declare(strict_types=1);

namespace App\Entity;

// INTENTIONALLY VULNERABLE — for demonstrating symfony-security-auditor.
// Do not deploy. Do not copy any of this into a real codebase.
final class User
{
    public ?int $id = null;

    public string $name = '';

    public string $email = '';

    public bool $isAdmin = false;

    /**
     * VULN: mass assignment — blindly copies every request field, including
     * `isAdmin`, into the entity. The fix is an explicit allow-list (Symfony
     * Form with `allow_extra_fields: false` and only the safe fields, or a
     * dedicated input DTO).
     *
     * @param array<string, mixed> $payload
     */
    public static function fromRequest(array $payload): self
    {
        $user = new self();
        foreach ($payload as $field => $value) {
            if (property_exists($user, $field)) {
                $user->{$field} = $value;
            }
        }

        return $user;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'isAdmin' => $this->isAdmin,
        ];
    }
}
