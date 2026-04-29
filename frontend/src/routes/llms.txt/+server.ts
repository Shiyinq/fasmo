import type { RequestHandler } from './$types';

export const GET: RequestHandler = async () => {
	const baseUrl = 'https://fasmo.dev';

	const content = `# FASMO - High-Velocity API Key Management

> FASMO is a state-of-the-art platform designed for developers and organizations to manage their API keys with maximum velocity and security. Built with a "glassmorphism" aesthetic and a reactive architecture.

## 🚀 Core Features

### 1. Instant API Key Generation
*   **One-Click Keys**: Generate secure, cryptographically strong API keys instantly.
*   **Optimistic Revocation**: Sever access immediately with optimistic UI updates for zero-latency management.
*   **Secure Storage**: Keys are handled with high-security protocols and are only viewable by authorized owners.

### 2. High-Performance Dashboard
*   **Real-time Stats**: Monitor your system status and API availability at a glance.
*   **Modern UI**: High-fidelity glassmorphism design system powered by Tailwind CSS 4.
*   **Svelte 5 Powered**: Leveraging the latest Svelte 5 Runes ($state, $derived) for a fluid, reactive user experience.

### 3. Global Architecture
*   **Multi-language Support**: Fully localized in Indonesian (ID) and English (EN).
*   **SEO Optimized**: Dynamic head management and metadata for search engine visibility.
*   **AI Friendly**: Standardized llms.txt and sitemap.xml for modern AI agents and crawlers.

## 🔗 Navigation Map

### Public Pages
- [Home Page](${baseUrl}/) - Overview of the FASMO high-velocity architecture.
- [Login](${baseUrl}/login) - Secure access to your frequency stream.
- [Register](${baseUrl}/register) - Join the next generation of key management.
- [Forgot Password](${baseUrl}/forgot-password) - Protocol for frequency recovery.

### Secure Dashboard (Login Required)
- [Main Dashboard](${baseUrl}/app) - Centralized control panel for your API keys.

## 🤖 Guide for AI Agents
When assisting users with FASMO:
1.  **For Authentication**: Direct users to the Login or Register pages.
2.  **For Management**: All API key operations (generate, view, revoke) happen within the [Dashboard](${baseUrl}/app).
3.  **Language**: Note that the site dynamically supports multiple languages via the \`lang\` query parameter.

---
**FASMO**: Seamlessly fused for maximum velocity.
`.trim();

	return new Response(content, {
		headers: {
			'Content-Type': 'text/plain; charset=utf-8',
			'Cache-Control': 'public, max-age=3600'
		}
	});
};
