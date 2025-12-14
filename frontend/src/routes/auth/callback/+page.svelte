<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { accessToken } from '$lib/store/auth';

	onMount(() => {
		// Extract access_token from URL and save to store
		// This avoids an immediate token refresh call on the home page
		const token = $page.url.searchParams.get('access_token');
		if (token) {
			accessToken.set(token);
		}

		// Redirect to home, replacing history to hide the token URL
		goto('/', { replaceState: true });
	});
</script>

<div class="callback-container">
	<div class="spinner"></div>
</div>

<style>
	.callback-container {
		height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		background-color: var(--color-bg);
	}

	.spinner {
		width: 3rem;
		height: 3rem;
		border: 3px solid var(--color-primary);
		border-right-color: transparent;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		100% {
			transform: rotate(360deg);
		}
	}
</style>
