<?php

declare(strict_types=1);

namespace App\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFilter;

// INTENTIONALLY VULNERABLE — for demonstrating symfony-security-auditor.
// Do not deploy. Do not copy any of this into a real codebase.
final class MarkupExtension extends AbstractExtension
{
    /**
     * @return list<TwigFilter>
     */
    public function getFilters(): array
    {
        return [
            // VULN: cross-site scripting via a filter declared
            // `is_safe => ['html']` while echoing caller-supplied input
            // verbatim. Marking output safe tells Twig to skip autoescaping, so
            // `{{ userBio|render_markup }}` injects unescaped attacker HTML. A
            // real fix drops `is_safe` (let Twig escape) or sanitizes with an
            // allow-list before returning.
            new TwigFilter('render_markup', $this->renderMarkup(...), ['is_safe' => ['html']]),
        ];
    }

    public function renderMarkup(string $value): string
    {
        return '<div class="markup">'.$value.'</div>';
    }
}
