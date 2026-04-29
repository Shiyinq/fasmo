// Centralized exports for all Svelte 5 stores
export * from './accessToken.svelte';
export * from './authStatus.svelte';
export * from './auth.svelte';
export * from './global.svelte';
export * from './toast.svelte';
export * from './apiKeys.svelte';

import { browser } from '$app/environment';
import { isAuthenticated } from './authStatus.svelte';
import { isInitialDataLoaded } from './global.svelte';

// Logout cleanup logic
if (browser) {
	isAuthenticated.subscribe((authenticated) => {
		if (!authenticated) {
			isInitialDataLoaded.value = false;
		}
	});
}
