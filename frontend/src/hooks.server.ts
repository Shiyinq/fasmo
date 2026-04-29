import type { Handle } from '@sveltejs/kit';
import { PUBLIC_SERVER_SIDE_API_BASE_URL } from '$env/static/public';
import { detectLocale } from '$lib/i18n/server';

export const handle: Handle = async ({ event, resolve }) => {
	// Health check endpoint
	if (event.url.pathname === '/health') {
		return new Response('OK', { status: 200 });
	}

	// Get locale for SSR
	const locale = detectLocale(event.request, event.cookies, event.url);

	// API Proxying
	if (event.url.pathname.startsWith('/api')) {
		const targetUrl = event.url.pathname.replace('/api', PUBLIC_SERVER_SIDE_API_BASE_URL);
		const requestHeaders = new Headers(event.request.headers);

		const targetUrlObj = new URL(targetUrl);
		requestHeaders.set('host', targetUrlObj.host);

		try {
			const response = await fetch(targetUrl + event.url.search, {
				method: event.request.method,
				headers: requestHeaders,
				body:
					event.request.method !== 'GET' && event.request.method !== 'HEAD'
						? await event.request.arrayBuffer()
						: undefined,
				// @ts-expect-error - duplex is needed for streaming bodies
				duplex: 'half'
			});

			return response;
		} catch (error) {
			console.error('Proxy error:', error);
			return new Response('Proxy Error', { status: 502 });
		}
	}

	return resolve(event, {
		transformPageChunk: ({ html }) => html.replace('%lang%', locale)
	});
};
