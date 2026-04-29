import { accessToken } from '$lib/stores/accessToken.svelte';
import { isAuthenticated } from '$lib/stores/authStatus.svelte';
import { isTokenExpired, getCSRFToken } from '$lib/utils/auth';
import type { ApiError, AuthResponse } from '$lib/types';
import { browser } from '$app/environment';

import { API_BASE, PUBLIC_ENDPOINTS, AUTH_STORAGE_KEY } from '$lib/constants';

// Removed hardcoded /api

// Lock to prevent multiple concurrent refresh token calls
let refreshPromise: Promise<string | null> | null = null;

async function refreshAccessToken(): Promise<string | null> {
	if (refreshPromise) return refreshPromise;

	refreshPromise = (async () => {
		try {
			const csrfToken = getCSRFToken();
			const response = await fetch(`${API_BASE}/auth/refresh`, {
				method: 'POST',
				headers: { 'X-CSRF-Token': csrfToken },
				credentials: 'include'
			});

			if (response.ok) {
				const data: AuthResponse = await response.json();
				accessToken.set(data.access_token);
				return data.access_token;
			}
			return null;
		} catch {
			return null;
		} finally {
			refreshPromise = null;
		}
	})();

	return refreshPromise;
}

export async function client<T>(
	endpoint: string,
	options: Omit<RequestInit, 'body'> & {
		body?: BodyInit | Record<string, unknown> | null;
		responseType?: 'json' | 'text' | 'blob';
	} = {}
): Promise<T> {
	let token: string = accessToken.value;

	const isPublic = PUBLIC_ENDPOINTS.some((p) => endpoint.startsWith(p));
	const hasAuthHint = browser ? localStorage.getItem(AUTH_STORAGE_KEY) === 'true' : false;

	if (isTokenExpired(token) && (!isPublic || hasAuthHint)) {
		const newToken = await refreshAccessToken();
		if (newToken) {
			token = newToken;
		} else {
			isAuthenticated.set(false);
			if (!isPublic) {
				token = '';
				// Return a promise that never resolves to silence the UI
				return new Promise(() => {});
			}
		}
	}

	const csrfToken = getCSRFToken();
	const defaultHeaders: Record<string, string> = {
		'Content-Type': 'application/json',
		'X-CSRF-Token': csrfToken
	};

	if (token) {
		defaultHeaders['Authorization'] = `Bearer ${token}`;
	}

	const config = {
		...options,
		headers: {
			...defaultHeaders,
			...options.headers
		},
		credentials: 'include' as RequestCredentials
	};

	if (
		config.body &&
		typeof config.body !== 'string' &&
		!(config.body instanceof FormData) &&
		!(config.body instanceof URLSearchParams)
	) {
		config.body = JSON.stringify(config.body);
	}

	const response = await fetch(`${API_BASE}${endpoint}`, config as RequestInit);

	if (response.status === 204) return undefined as T;

	if (!response.ok) {
		let errorData: unknown;
		const contentType = response.headers.get('content-type');
		if (contentType && contentType.includes('application/json')) {
			errorData = await response.json();
		} else {
			errorData = await response.text();
		}

		const error =
			typeof errorData === 'object' && errorData !== null
				? { ...errorData, status: response.status }
				: { detail: errorData, status: response.status };

		throw error as ApiError;
	}

	if (options.responseType === 'blob') return (await response.blob()) as T;
	if (options.responseType === 'text') return (await response.text()) as T;

	const contentType = response.headers.get('content-type');
	if (contentType && contentType.includes('application/json')) {
		return (await response.json()) as T;
	}
	return (await response.text()) as T;
}
