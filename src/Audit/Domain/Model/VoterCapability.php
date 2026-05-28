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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

final readonly class VoterCapability
{
    /**
     * @param list<string> $supportedAttributes attribute names the voter's `supports()` accepts (e.g. `EDIT`, `DELETE`)
     * @param list<string> $supportedSubjects   fully-qualified or short class names of subjects the voter's `supports()` accepts (e.g. `App\Entity\User`)
     */
    public function __construct(
        private string $filePath,
        private string $className,
        private array $supportedAttributes,
        private array $supportedSubjects,
    ) {}

    public function filePath(): string
    {
        return $this->filePath;
    }

    public function className(): string
    {
        return $this->className;
    }

    /**
     * @return list<string>
     */
    public function supportedAttributes(): array
    {
        return $this->supportedAttributes;
    }

    /**
     * @return list<string>
     */
    public function supportedSubjects(): array
    {
        return $this->supportedSubjects;
    }

    public function coversAttribute(string $attribute): bool
    {
        return \in_array($attribute, $this->supportedAttributes, true);
    }

    public function coversSubject(string $subject): bool
    {
        foreach ($this->supportedSubjects as $supportedSubject) {
            if ($supportedSubject === $subject) {
                return true;
            }

            $parts = explode('\\', $supportedSubject);
            if (end($parts) === $subject) {
                return true;
            }
        }

        return false;
    }
}
