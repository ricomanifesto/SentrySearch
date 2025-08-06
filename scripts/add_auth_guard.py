#!/usr/bin/env python3
"""
Script to add AuthGuard to protected pages
"""

import os
import re

# Pages that need authentication
protected_pages = [
    'frontend/src/app/analytics/page.tsx',
    'frontend/src/app/generate/page.tsx',
    'frontend/src/app/export/page.tsx',
    'frontend/src/app/search/page.tsx',
    'frontend/src/app/admin/page.tsx',
    'frontend/src/app/settings/page.tsx'
]

def add_auth_guard_to_page(file_path):
    """Add AuthGuard import and wrapper to a page"""
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Skip if already has AuthGuard
    if 'AuthGuard' in content:
        print(f"AuthGuard already added to {file_path}")
        return
    
    # Add import
    import_pattern = r"(import .* from '@/components/ui/.*';)"
    if re.search(import_pattern, content):
        content = re.sub(
            import_pattern,
            r"\1\nimport { AuthGuard } from '@/components/AuthGuard';",
            content,
            count=1
        )
    else:
        # Add after other imports
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if line.startswith('export default function'):
                lines.insert(i, "import { AuthGuard } from '@/components/AuthGuard';")
                lines.insert(i, "")
                break
        content = '\n'.join(lines)
    
    # Wrap return statement
    content = re.sub(
        r'(\s+return \(\s*<div)',
        r'\1\n    <AuthGuard>\2',
        content
    )
    
    # Add closing tag before last closing parentheses and brace
    content = re.sub(
        r'(\s+</div>\s+\);\s*})\s*$',
        r'\1\n    </AuthGuard>\2',
        content
    )
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Added AuthGuard to {file_path}")

def main():
    base_path = os.path.dirname(os.path.dirname(__file__))
    
    for page_path in protected_pages:
        full_path = os.path.join(base_path, page_path)
        add_auth_guard_to_page(full_path)

if __name__ == "__main__":
    main()