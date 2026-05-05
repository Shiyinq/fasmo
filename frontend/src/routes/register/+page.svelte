<script lang="ts">
	import { authStore } from '$lib/stores';
	import { goto } from '$app/navigation';
	import { fade, fly, slide } from 'svelte/transition';
	import { useTranslation } from '$lib/i18n/useTranslation';
	import LanguageSwitcher from '$lib/components/common/LanguageSwitcher.svelte';
	import ThemeToggle from '$lib/components/common/ThemeToggle.svelte';
	import SEO from '$lib/components/common/SEO.svelte';
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
	import { Check, ArrowRight } from 'lucide-svelte';

	const { t } = useTranslation();

	let step = $state(1);

	let name = $state('');
	let username = $state('');
	let email = $state('');
	let password = $state('');
	let confirmPassword = $state('');

	let reqLength = $derived(password.length > 7);
	let reqNumber = $derived(/[0-9]/.test(password));
	let reqSpecial = $derived(/[^A-Za-z0-9]/.test(password));
	let reqMatch = $derived(password.length > 0 && password === confirmPassword);

	let loading = $derived(authStore.isLoading);
	let error = $derived(authStore.error);

	let passwordStrength = $derived(calculateStrength(password));

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

	async function handleRegister() {
		if (step === 1) {
			nextStep();
			return;
		}

		if (password !== confirmPassword) {
			return;
		}

		try {
			await authStore.register({ name, username, email, password, confirmPassword });
			await authStore.login({ username: email, password });
			goto('/app');
		} catch (e: unknown) {
			logger.error('Registration failed', e, { context: 'register' });
		}
	}

	function nextStep() {
		if (step === 1) {
			if (!name || !username) {
				return;
			}
			step = 2;
		}
	}

	function prevStep() {
		step = 1;
	}

	function handleSocialLogin(provider: 'google' | 'github') {
		if (provider === 'google') {
			window.location.href = authStore.googleLoginUrl;
		} else if (provider === 'github') {
			window.location.href = authStore.githubLoginUrl;
		}
	}
</script>

<SEO title="FASMO | {t('common.register')}" description={t('auth.seo.register_desc')} />

<div class="min-h-screen flex items-center justify-center p-6 bg-background relative">
	<div class="absolute top-6 right-6 z-50 flex items-center gap-2">
		<LanguageSwitcher />
		<ThemeToggle />
	</div>

	<div class="w-full max-w-md" in:fade={{ duration: 200 }}>
		<Card class="border-border overflow-hidden">
			<CardHeader class="space-y-2 text-center pb-6">
				<CardTitle class="text-3xl font-bold tracking-tight">{t('common.register')}</CardTitle>
				<CardDescription>{t('auth.register_subtitle')}</CardDescription>

				<div class="flex items-center justify-center gap-2 pt-4">
					<div
						class="w-2.5 h-2.5 rounded-full transition-colors {step >= 1
							? 'bg-primary'
							: 'bg-muted'}"
					></div>
					<div
						class="w-8 h-1 rounded-full transition-colors {step >= 2 ? 'bg-primary' : 'bg-muted'}"
					></div>
					<div
						class="w-2.5 h-2.5 rounded-full transition-colors {step >= 2
							? 'bg-primary'
							: 'bg-muted'}"
					></div>
				</div>
			</CardHeader>
			<CardContent>
				<form
					class="space-y-4"
					onsubmit={(e) => {
						e.preventDefault();
						handleRegister();
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

					<div class="relative min-h-[300px]">
						{#if step === 1}
							<div
								class="space-y-4 absolute inset-0 w-full"
								in:fly={{ x: -20, duration: 400 }}
								out:fly={{ x: 20, duration: 400 }}
							>
								<div class="grid gap-2">
									<Label for="name">{t('auth.full_name')}</Label>
									<Input
										id="name"
										type="text"
										placeholder={t('auth.full_name_placeholder')}
										bind:value={name}
										required
									/>
								</div>

								<div class="grid gap-2">
									<Label for="username">{t('common.username')}</Label>
									<Input
										id="username"
										type="text"
										placeholder={t('auth.username_placeholder')}
										bind:value={username}
										required
									/>
								</div>

								<Button type="submit" class="w-full mt-6">
									{t('auth.next')}
									<ArrowRight class="ml-2 w-4 h-4" />
								</Button>
							</div>
						{:else}
							<div
								class="space-y-4 absolute inset-0 w-full"
								in:fly={{ x: 20, duration: 400 }}
								out:fly={{ x: -20, duration: 400 }}
							>
								<div class="grid gap-2">
									<Label for="email">{t('common.email')}</Label>
									<Input
										id="email"
										type="email"
										placeholder={t('auth.email_placeholder')}
										bind:value={email}
										required
									/>
								</div>

								<div class="grid gap-2">
									<Label for="password">{t('common.password')}</Label>
									<Input
										id="password"
										type="password"
										placeholder="••••••••"
										bind:value={password}
										required
									/>

									{#if password}
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
									<Label for="confirm">{t('auth.confirm_password')}</Label>
									<Input
										id="confirm"
										type="password"
										placeholder="••••••••"
										bind:value={confirmPassword}
										required
									/>

									{#if password}
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

								<div class="flex gap-2 mt-6">
									<Button type="button" variant="outline" class="w-1/3" onclick={prevStep}
										>{t('auth.back')}</Button
									>
									<Button type="submit" class="w-2/3" {loading}>
										{#if !loading}
											{t('common.register')}
										{:else}
											{t('auth.creating_account')}
										{/if}
									</Button>
								</div>
							</div>
						{/if}
					</div>
				</form>
			</CardContent>
			<CardFooter class="flex flex-col space-y-4 pt-4 border-t border-border mt-4">
				<div class="relative w-full">
					<div class="absolute inset-0 flex items-center">
						<span class="w-full border-t border-muted"></span>
					</div>
					<div class="relative flex justify-center text-xs uppercase">
						<span class="bg-card px-2 text-muted-foreground">{t('auth.or_continue_with')}</span>
					</div>
				</div>

				<div class="grid grid-cols-2 gap-4 w-full">
					<Button variant="outline" onclick={() => handleSocialLogin('google')} class="w-full">
						<svg class="mr-2 h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
							<path
								d="M12.545,10.239v3.821h5.445c-0.712,2.315-2.647,3.972-5.445,3.972c-3.332,0-6.033-2.701-6.033-6.032s2.701-6.032,6.033-6.032c1.498,0,2.866,0.549,3.921,1.453l2.814-2.814C17.503,2.988,15.139,2,12.545,2C7.021,2,2.543,6.477,2.543,12s4.478,10,10.002,10c8.396,0,10.249-7.85,9.426-11.748L12.545,10.239z"
							/>
						</svg>
						{t('common.google')}
					</Button>
					<Button variant="outline" onclick={() => handleSocialLogin('github')} class="w-full">
						<svg class="mr-2 h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
							<path
								d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"
							/>
						</svg>
						{t('common.github')}
					</Button>
				</div>

				<div class="text-center text-sm text-muted-foreground mt-4">
					{t('auth.already_have_account')}
					<a href="/login" class="font-medium text-primary hover:underline ml-1">
						{t('common.login')}
					</a>
				</div>
			</CardFooter>
		</Card>
	</div>
</div>
