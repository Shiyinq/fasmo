<script lang="ts">
	import { page } from '$app/state';
	import { authStore } from '$lib/stores';
	import { onMount } from 'svelte';
	import { fade, scale } from 'svelte/transition';
	import { useTranslation } from '$lib/i18n/useTranslation';
	import SEO from '$lib/components/common/SEO.svelte';
	import {
		Card,
		CardHeader,
		CardTitle,
		CardDescription,
		CardContent
	} from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import LanguageSwitcher from '$lib/components/common/LanguageSwitcher.svelte';
	import ThemeToggle from '$lib/components/common/ThemeToggle.svelte';
	import { Loader2, CheckCircle2, XCircle } from 'lucide-svelte';

	const { t } = useTranslation();

	type VerificationStatus = 'verifying' | 'success' | 'error';

	let status = $state<VerificationStatus>('verifying');
	let localError = $state('');
	let errorMessage = $derived(localError || authStore.error);

	onMount(async () => {
		const token = page.url.searchParams.get('token');

		if (!token) {
			status = 'error';
			localError = t('auth.verify_email.no_token');
			return;
		}

		try {
			await authStore.verifyEmail({ token });
			status = 'success';
		} catch (_e: any) {
			status = 'error';
		}
	});
</script>

<SEO title="FASMO | {t('auth.verify_email.title')}" description={t('auth.seo.verify_desc')} />

<div class="min-h-screen flex items-center justify-center p-6 bg-background relative">
	<div class="absolute top-6 right-6 z-50 flex items-center gap-2">
		<LanguageSwitcher />
		<ThemeToggle />
	</div>
	<div class="w-full max-w-md" in:fade={{ duration: 200 }}>
		<Card class="border-border">
			<CardHeader class="space-y-2 text-center pb-6">
				{#if status === 'verifying'}
					<div in:fade>
						<CardTitle class="text-3xl font-bold tracking-tight"
							>{t('auth.verify_email.verifying')}</CardTitle
						>
					</div>
					<CardDescription>{t('auth.verify_email.verifying_subtitle')}</CardDescription>
				{:else if status === 'success'}
					<div in:fade>
						<CardTitle class="text-3xl font-bold tracking-tight text-green-500"
							>{t('auth.verify_email.verified')}</CardTitle
						>
					</div>
					<CardDescription>{t('auth.verify_email.verified_subtitle')}</CardDescription>
				{:else}
					<div in:fade>
						<CardTitle class="text-3xl font-bold tracking-tight text-destructive"
							>{t('auth.verify_email.failed')}</CardTitle
						>
					</div>
					<CardDescription>{t('auth.verify_email.failed_subtitle')}</CardDescription>
				{/if}
			</CardHeader>

			<CardContent class="flex flex-col items-center justify-center min-h-[200px] text-center">
				{#if status === 'verifying'}
					<div class="flex flex-col items-center gap-4" in:fade>
						<Loader2 class="w-12 h-12 animate-spin text-primary" />
						<div>
							<h2 class="text-lg font-bold">{t('auth.verify_email.status_verifying')}</h2>
							<p class="text-sm text-muted-foreground">
								{t('auth.verify_email.status_verifying_desc')}
							</p>
						</div>
					</div>
				{:else if status === 'success'}
					<div class="flex flex-col items-center gap-4" in:scale={{ duration: 500 }}>
						<div
							class="w-16 h-16 bg-green-500/10 rounded-full flex items-center justify-center text-green-500"
						>
							<CheckCircle2 class="w-8 h-8" />
						</div>
						<div>
							<h2 class="text-xl font-bold">{t('auth.verify_email.status_success')}</h2>
							<p class="text-sm text-muted-foreground">
								{t('auth.verify_email.status_success_desc')}
							</p>
						</div>
						<Button href="/login" class="w-full mt-4"
							>{t('auth.verify_email.proceed_to_login')}</Button
						>
					</div>
				{:else}
					<div class="flex flex-col items-center gap-4" in:scale={{ duration: 500 }}>
						<div
							class="w-16 h-16 bg-destructive/10 rounded-full flex items-center justify-center text-destructive"
						>
							<XCircle class="w-8 h-8" />
						</div>
						<div>
							<h2 class="text-xl font-bold text-destructive">
								{t('auth.verify_email.status_error')}
							</h2>
							<p class="text-sm text-muted-foreground">{errorMessage}</p>
						</div>
						<Button href="/login" variant="outline" class="w-full mt-4"
							>{t('auth.back_to_login')}</Button
						>
					</div>
				{/if}
			</CardContent>
		</Card>
	</div>
</div>
