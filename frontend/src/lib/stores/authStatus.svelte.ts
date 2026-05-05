import { browser } from '$app/environment';

/**
 * Authentication status store - migrated to Svelte 5 Shared Rune State.
 * Handles persistence to localStorage and Cookies for SSR support.
 */

export const AUTH_KEY = 'fasmo_auth';

let authenticated = $state(browser ? localStorage.getItem(AUTH_KEY) === 'true' : false);

export const isAuthenticated = {
	get value() {
		return authenticated;
	},
	set: (val: boolean) => {
		authenticated = val;
		if (browser) {
			if (val) {
				localStorage.setItem(AUTH_KEY, 'true');
				document.cookie = `${AUTH_KEY}=true; path=/; max-age=31536000; SameSite=Lax`;
			} else {
				localStorage.removeItem(AUTH_KEY);
				document.cookie = `${AUTH_KEY}=; path=/; max-age=0; SameSite=Lax`;
			}
		}
	},
	// Compatibility for legacy store-like access
	set value(v: boolean) {
		this.set(v);
	},

	subscribe: (fn: (val: boolean) => void) => {
		fn(authenticated);
		$effect.root(() => {
			$effect(() => {
				fn(authenticated);
			});
		});
		return () => {};
	}
};
