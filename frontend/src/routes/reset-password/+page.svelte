<script lang="ts">
	import { page } from '$app/state';
	import { authStore } from '$lib/stores';
	import { addToast } from '$lib/stores';
	import { onMount } from 'svelte';
	import { fade, slide } from 'svelte/transition';
	import { useTranslation } from '$lib/i18n/useTranslation';
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
	import LanguageSwitcher from '$lib/components/common/LanguageSwitcher.svelte';
	import ThemeToggle from '$lib/components/common/ThemeToggle.svelte';
	import { logger } from '$lib/utils/logger';
	import { Check } from 'lucide-svelte';

	const { t } = useTranslation();

	let newPassword = $state('');
	let confirmPassword = $state('');
	let loading = $derived(authStore.isLoading);
	let error = $derived(authStore.error);
	let success = $state(false);
	let token = $state('');

	let reqLength = $derived(newPassword.length > 7);
	let reqNumber = $derived(/[0-9]/.test(newPassword));
	let reqSpecial = $derived(/[^A-Za-z0-9]/.test(newPassword));
	let reqMatch = $derived(newPassword.length > 0 && newPassword === confirmPassword);

	let passwordStrength = $derived(calculateStrength(newPassword));

	function calculateStrength(pw: string) {
		if (!pw) return 0;
		let score = 0;
		if (pw.length > 7) score++;
		if (/[A-Z]/.test(pw)) score++;
		if (/[0-9]/.test(pw)) score++;
		if (/[^A-Za-z0-9]/.test(pw)) score++;
		return score;
	}

	function getStrengthColor(score: number) {
		if (score < 2) return 'bg-destructive';
		if (score < 4) return 'bg-orange-500';
		return 'bg-green-500';
	}

	let allValid = $derived(reqLength && reqNumber && reqSpecial && reqMatch);

	onMount(() => {
		token = page.url.searchParams.get('token') || '';
		if (!token) {
			error = t('errors.token_invalid');
		}
	});

	async function handleSubmit() {
		if (!token) {
			error = t('errors.signal_lost');
			return;
		}

		if (!allValid) {
			error = t('errors.security_req');
			return;
		}

		try {
			await authStore.resetPassword({
				token,
				new_password: newPassword,
				confirm_password: confirmPassword
			});
			success = true;
			addToast('Frequency re-established.', 'success');
			setTimeout(() => {
				window.location.href = '/login';
			}, 2000);
		} catch (e: unknown) {
			logger.error('Reset password failed', e, { context: 'reset-password' });
			addToast(authStore.error, 'error');
		}
	}
</script>

<svelte:head>
	<title>FASMO | {t('auth.reset_password')}</title>
	<meta name="robots" content="noindex, nofollow" />
</svelte:head>

<div class="min-h-screen flex items-center justify-center p-6 bg-background relative">
	<div class="absolute top-6 right-6 z-50 flex items-center gap-2">
		<LanguageSwitcher />
		<ThemeToggle />
	</div>
	<div class="w-full max-w-md" in:fade={{ duration: 200 }}>
		<Card class="border-border">
			<CardHeader class="space-y-2 text-center pb-6">
				<CardTitle class="text-3xl font-bold tracking-tight">SECURE</CardTitle>
				<CardDescription>{t('auth.reset_password_subtitle')}</CardDescription>
			</CardHeader>
			<CardContent>
				{#if success}
					<div class="flex flex-col items-center text-center space-y-4" in:fade>
						<div
							class="w-16 h-16 bg-green-500/10 rounded-full flex items-center justify-center text-green-500 mb-2"
						>
							<Check class="w-8 h-8" />
						</div>
						<h2 class="text-xl font-bold">{t('auth.reset_password')}</h2>
						<p class="text-sm text-muted-foreground">
							{t('auth.reset_success')}
						</p>
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

						<div class="grid gap-2">
							<Label for="new-password">{t('auth.new_password')}</Label>
							<Input
								id="new-password"
								type="password"
								placeholder="••••••••"
								bind:value={newPassword}
								required
							/>

							{#if newPassword}
								<div class="flex gap-1 mb-2" transition:slide>
									{#each Array(4) as _, i}
										<div
											class="h-1 flex-1 rounded-full {passwordStrength > i
												? getStrengthColor(passwordStrength)
												: 'bg-muted'} transition-colors"
										></div>
									{/each}
								</div>
							{/if}
						</div>

						<div class="grid gap-2">
							<Label for="confirm-password">{t('auth.confirm_password')}</Label>
							<Input
								id="confirm-password"
								type="password"
								placeholder="••••••••"
								bind:value={confirmPassword}
								required
							/>

							{#if newPassword}
								<div
									class="grid grid-cols-2 gap-2 text-xs text-muted-foreground mt-2"
									transition:slide
								>
									<div class="flex items-center gap-1 {reqLength ? 'text-green-500' : ''}">
										<Check class="w-3 h-3 {reqLength ? 'opacity-100' : 'opacity-30'}" />
										{t('auth.req_length')}
									</div>
									<div class="flex items-center gap-1 {reqNumber ? 'text-green-500' : ''}">
										<Check class="w-3 h-3 {reqNumber ? 'opacity-100' : 'opacity-30'}" />
										{t('auth.req_number')}
									</div>
									<div class="flex items-center gap-1 {reqSpecial ? 'text-green-500' : ''}">
										<Check class="w-3 h-3 {reqSpecial ? 'opacity-100' : 'opacity-30'}" />
										{t('auth.req_special')}
									</div>
									<div class="flex items-center gap-1 {reqMatch ? 'text-green-500' : ''}">
										<Check class="w-3 h-3 {reqMatch ? 'opacity-100' : 'opacity-30'}" />
										{t('auth.req_match')}
									</div>
								</div>
							{/if}
						</div>

						<Button type="submit" class="w-full mt-6" disabled={!allValid} {loading}>
							{#if !loading}
								{t('auth.reset_password').toUpperCase()}
							{:else}
								{t('auth.resetting')}
							{/if}
						</Button>
					</form>
				{/if}
			</CardContent>
			{#if !success}
				<CardFooter class="flex justify-center pt-4 border-t border-border mt-4">
					<a
						href="/login"
						class="text-sm text-muted-foreground hover:text-foreground transition-colors"
					>
						{t('common.cancel')}
					</a>
				</CardFooter>
			{/if}
		</Card>
	</div>
</div>
