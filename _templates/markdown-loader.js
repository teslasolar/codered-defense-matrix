// Markdown Loader for CodeRED Defense Matrix
// Parses index.md files and renders content

async function loadMarkdownConfig(mdFile) {
    try {
        const response = await fetch(mdFile);
        const text = await response.text();

        // Parse the markdown
        const config = parseMarkdown(text);

        // Update page with configuration
        updatePage(config);

        // Render markdown content
        renderMarkdown(config.content);
    } catch (error) {
        console.error('Error loading markdown:', error);
        document.getElementById('markdown-content').innerHTML =
            '<p style="color: #ff0040;">Error loading content. Please check index.md file.</p>';
    }
}

function parseMarkdown(text) {
    const lines = text.split('\n');
    const config = {
        title: '',
        icon: '',
        description: '',
        section: '',
        metadata: {},
        content: ''
    };

    let inFrontmatter = false;
    let contentStart = 0;

    // Parse frontmatter (YAML-style)
    if (lines[0] === '---') {
        inFrontmatter = true;

        for (let i = 1; i < lines.length; i++) {
            if (lines[i] === '---') {
                contentStart = i + 1;
                break;
            }

            const [key, ...valueParts] = lines[i].split(':');
            if (key && valueParts.length > 0) {
                const value = valueParts.join(':').trim();
                config.metadata[key.trim()] = value;

                // Map common fields
                if (key.trim() === 'title') config.title = value;
                if (key.trim() === 'icon') config.icon = value;
                if (key.trim() === 'description') config.description = value;
                if (key.trim() === 'section') config.section = value;
            }
        }
    }

    // Get content after frontmatter
    config.content = lines.slice(contentStart).join('\n');

    return config;
}

function updatePage(config) {
    // Update title
    if (config.title) {
        document.title = `${config.title} - CodeRED Defense Matrix`;
        const h1 = document.querySelector('.section-header h1');
        if (h1) {
            h1.textContent = `${config.icon || ''} ${config.title}`;
        }
    }

    // Update description
    if (config.description) {
        const desc = document.querySelector('.description');
        if (desc) {
            desc.textContent = config.description;
        }
    }

    // Update navigation
    if (config.section) {
        const navCurrent = document.querySelector('.nav-current');
        if (navCurrent) {
            navCurrent.textContent = config.section;
        }
    }
}

function renderMarkdown(markdown) {
    const container = document.getElementById('markdown-content');
    if (!container) return;

    // Simple markdown to HTML converter
    let html = markdown;

    // Headers
    html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');
    html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
    html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');

    // Bold and italic
    html = html.replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');

    // Links
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Code blocks
    html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, function(match, lang, code) {
        return `<pre><code class="language-${lang || 'text'}">${escapeHtml(code.trim())}</code></pre>`;
    });

    // Lists
    html = html.replace(/^\* (.+)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
    html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');

    // Blockquotes
    html = html.replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>');

    // Tables (simple)
    html = html.replace(/\|(.+)\|/g, function(match, content) {
        const cells = content.split('|').map(cell => cell.trim());
        if (cells.every(cell => cell.match(/^-+$/))) {
            return ''; // Skip separator rows
        }
        const row = cells.map(cell => `<td>${cell}</td>`).join('');
        return `<tr>${row}</tr>`;
    });
    html = html.replace(/(<tr>.*<\/tr>)/s, '<table>$1</table>');

    // Paragraphs
    html = html.replace(/\n\n/g, '</p><p>');
    html = '<p>' + html + '</p>';

    // Clean up empty paragraphs
    html = html.replace(/<p>\s*<\/p>/g, '');
    html = html.replace(/<p>(<h[1-6]>)/g, '$1');
    html = html.replace(/(<\/h[1-6]>)<\/p>/g, '$1');

    // Special components
    html = renderSpecialComponents(html);

    container.innerHTML = html;

    // Add syntax highlighting if available
    if (typeof hljs !== 'undefined') {
        container.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
        });
    }
}

function renderSpecialComponents(html) {
    // File lists
    html = html.replace(/\{\{files:([^}]+)\}\}/g, function(match, path) {
        return renderFileList(path);
    });

    // Card grids
    html = html.replace(/\{\{cards:start\}\}([\s\S]*?)\{\{cards:end\}\}/g, function(match, content) {
        return `<div class="cards-grid">${content}</div>`;
    });

    // Badges
    html = html.replace(/\{\{badge:(\w+):([^}]+)\}\}/g, function(match, type, text) {
        return `<span class="badge badge-${type}">${text}</span>`;
    });

    return html;
}

function renderFileList(path) {
    // This would normally fetch the file list from the server
    // For now, return a placeholder
    return `
        <ul class="file-list">
            <li class="file-item">
                <span class="file-icon">📄</span>
                <a href="${path}">View files in ${path}</a>
            </li>
        </ul>
    `;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Auto-initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    // Check if there's an index.md to load
    if (typeof indexMdPath !== 'undefined') {
        loadMarkdownConfig(indexMdPath);
    }
});