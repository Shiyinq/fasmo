<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { isAuthenticated, authStore, isInitialDataLoaded } from '$lib/stores';
	import { locale, type Locale } from '$lib/i18n';
	import { ModeWatcher } from 'mode-watcher';
	import { Toaster } from '$lib/components/ui/sonner';
	import LoadingBar from '$lib/components/LoadingBar.svelte';
	import SplashScreen from '$lib/components/SplashScreen.svelte';
	import SEO from '$lib/components/common/SEO.svelte';
	import { logger } from '$lib/utils/logger';

	interface Props {
		data: { locale: string };
		children: import('svelte').Snippet;
	}

	let { data, children }: Props = $props();

	// Hydrate locale from server data
	$effect(() => {
		if (data?.locale) {
			locale.value = data.locale as Locale;
		}
	});

	let mounted = $state(false);

	onMount(() => {
		mounted = true;
	});

	// Check if the current page is public
	let isPublicPage = $derived(
		page.url.pathname === '/' ||
			page.url.pathname === '/login' ||
			page.url.pathname === '/register' ||
			page.url.pathname === '/forgot-password' ||
			page.url.pathname === '/reset-password' ||
			page.url.pathname.startsWith('/auth/')
	);

	// Check if the current page is for guests only
	let isGuestRoute = $derived(
		page.url.pathname === '/login' ||
			page.url.pathname === '/register' ||
			page.url.pathname === '/forgot-password' ||
			page.url.pathname === '/reset-password'
	);

	// Fetch initial data (profile) if authenticated
	async function fetchInitialData() {
		if (isInitialDataLoaded.value) return;
		try {
			await authStore.getProfile();
		} catch (err) {
			logger.error('Failed to load profile', err, { context: 'layout' });
		} finally {
			isInitialDataLoaded.value = true;
		}
	}

	// Reactive Auth Guard
	$effect(() => {
		if (mounted) {
			if (isAuthenticated.value) {
				fetchInitialData();
				if (isGuestRoute) {
					goto('/app');
				}
			} else if (!isPublicPage) {
				goto('/login');
			}
		}
	});
</script>

<SEO />
<ModeWatcher />

<div class="min-h-screen flex flex-col relative overflow-x-hidden">
	{#if !mounted}
		<SplashScreen />
	{:else}
		<LoadingBar />
		<main class="flex-1 w-full relative">
			{@render children()}
		</main>
		<Toaster position="bottom-right" richColors />
	{/if}
</div>
