<script lang="ts">
	import { authStore } from '$lib/stores';
	import { fade } from 'svelte/transition';
	import { useTranslation } from '$lib/i18n/useTranslation';
	import LanguageSwitcher from '$lib/components/common/LanguageSwitcher.svelte';
	import ThemeToggle from '$lib/components/common/ThemeToggle.svelte';
	import { Input } from '$lib/components/ui/input';
	import { Button } from '$lib/components/ui/button';
	import { Label } from '$lib/components/ui/label';
	import {
		Card,
		CardHeader,
		CardTitle,
		CardDescription,
		CardContent,
		CardFooter
	} from '$lib/components/ui/card';
	import { logger } from '$lib/utils/logger';

	const { t } = useTranslation();

	let email = $state('');
	let loading = $derived(authStore.isLoading);
	let error = $derived(authStore.error);
	let success = $state(false);

	async function handleSubmit() {
		try {
			await authStore.forgotPassword({ email });
			success = true;
		} catch (e: any) {
			logger.error('Forgot password failed', e, { context: 'forgot-password' });
		}
	}
</script>

<svelte:head>
	<title>FASMO | {t('auth.forgot_password')}</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center p-6 bg-background relative">
	<div class="absolute top-6 right-6 z-50 flex items-center gap-2">
		<LanguageSwitcher />
		<ThemeToggle />
	</div>

	<div class="w-full max-w-md" in:fade={{ duration: 200 }}>
		<Card class="border-border">
			<CardHeader class="space-y-2 text-center pb-8">
				<CardTitle class="text-3xl font-bold tracking-tight"
					>{t('auth.forgot_password').toUpperCase()}</CardTitle
				>
				<CardDescription>{t('auth.forgot_password_subtitle')}</CardDescription>
			</CardHeader>
			<CardContent>
				{#if success}
					<div class="flex flex-col items-center text-center space-y-4" in:fade>
						<div
							class="w-16 h-16 bg-green-500/10 rounded-full flex items-center justify-center text-green-500 mb-2"
						>
							<svg viewBox="0 0 24 24" fill="none" class="w-8 h-8">
								<path
									d="M20 6L9 17L4 12"
									stroke="currentColor"
									stroke-width="2"
									stroke-linecap="round"
									stroke-linejoin="round"
								/>
							</svg>
						</div>
						<h2 class="text-xl font-bold">{t('auth.check_inbox')}</h2>
						<p class="text-sm text-muted-foreground">
							{t('auth.recovery_sent')} <strong class="text-foreground">{email}</strong>.
						</p>
						<Button href="/login" variant="outline" class="w-full mt-4"
							>{t('auth.back_to_login')}</Button
						>
					</div>
				{:else}
					<form
						class="space-y-4"
						onsubmit={(e) => {
							e.preventDefault();
							handleSubmit();
						}}
					>
						{#if error}
							<div
								class="bg-destructive/15 text-destructive text-sm p-3 rounded-md flex items-center gap-2 mb-4"
								transition:fade
							>
								<span
									class="w-5 h-5 flex items-center justify-center rounded-full bg-destructive text-destructive-foreground font-bold text-xs"
									>!</span
								>
								{error}
							</div>
						{/if}

						<div class="grid gap-2 text-left">
							<Label for="email" class="mb-1">{t('common.email')}</Label>
							<p class="text-xs text-muted-foreground mb-1">{t('auth.recovery_helper')}</p>
							<Input
								id="email"
								type="email"
								placeholder={t('auth.email_placeholder')}
								bind:value={email}
								required
							/>
						</div>

						<Button type="submit" class="w-full mt-4" {loading}>
							{#if !loading}
								{t('auth.send_reset_link').toUpperCase()}
							{:else}
								{t('common.loading')}
							{/if}
						</Button>
					</form>
				{/if}
			</CardContent>
			{#if !success}
				<CardFooter class="flex justify-center pt-4 border-t border-border mt-4">
					<a
						href="/login"
						class="text-sm text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
					>
						← {t('auth.back_to_login')}
					</a>
				</CardFooter>
			{/if}
		</Card>
	</div>
</div>
