<script lang="ts">
	import { fly } from 'svelte/transition';
	import { useTranslation } from '$lib/i18n/useTranslation';
	import LanguageSwitcher from '$lib/components/common/LanguageSwitcher.svelte';
	import ThemeToggle from '$lib/components/common/ThemeToggle.svelte';
	import SEO from '$lib/components/common/SEO.svelte';
	import { Button } from '$lib/components/ui/button';
	import { Card, CardHeader, CardTitle, CardContent } from '$lib/components/ui/card';
	import { isAuthenticated } from '$lib/stores/authStatus.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Zap, Shield, Sparkles, LayoutDashboard } from 'lucide-svelte';

	const { t } = useTranslation();
</script>

<SEO title="FASMO | {t('landing.hero')}" description={t('landing.tagline')} />

<div
	class="min-h-screen flex flex-col items-center justify-center text-center overflow-hidden bg-background"
>
	<nav class="absolute top-0 right-0 w-full flex justify-end items-center gap-3 z-10 p-4 md:p-6">
		<LanguageSwitcher />
		<ThemeToggle />
		{#if isAuthenticated.value}
			<Button href="/app" variant="default" size="sm" class="rounded-full px-6 gap-2">
				<LayoutDashboard class="w-4 h-4" />
				{t('dashboard.title')}
			</Button>
		{:else}
			<Button
				href="/login"
				variant="ghost"
				size="sm"
				class="text-muted-foreground hover:text-foreground"
			>
				{t('common.login')}
			</Button>
			<Button href="/register" size="sm" class="rounded-full px-6">
				{t('common.register')}
			</Button>
		{/if}
	</nav>

	<div
		class="max-w-5xl w-full flex flex-col items-center justify-center gap-12 px-6"
		in:fly={{ y: 20, duration: 1000 }}
	>
		<header class="flex flex-col items-center gap-6 w-full">
			<pre
				class="font-mono font-bold leading-tight whitespace-pre m-0 select-none text-center text-foreground/90 text-sm md:text-base lg:text-lg">
		('-.      .-')   _   .-')                
	   ( OO ).-. ( OO ).( '.( OO )_              
,------./ . --. /(_)---\_),--.   ,--.).-'),-----. 
('-| _.---'| \-.  \ /    _ | |   `.'   |( OO'  .-.  '
(OO|(_\  .-'-'  |  |\  :` `. |         |/   |  | |  |
/  |  '--.\| |_.'  | '..`''.)|  |'.'|  |\_) |  |\|  |
\_)|  .--' |  .-.  |.-._)   \|  |   |  |  \ |  | |  |
  \|  |_)  |  | |  |\       /|  |   |  |   `'  '-'  '
   `--'    `--' `--' `-----' `--'   `--'     `-----'
			</pre>

			<div class="flex items-center gap-2">
				<Badge
					variant="secondary"
					class="px-4 py-1 rounded-full font-mono text-[10px] uppercase tracking-widest bg-muted/50 border-muted"
					>FastAPI</Badge
				>
				<Badge
					variant="secondary"
					class="px-4 py-1 rounded-full font-mono text-[10px] uppercase tracking-widest bg-muted/50 border-muted"
					>SvelteKit</Badge
				>
				<Badge
					variant="secondary"
					class="px-4 py-1 rounded-full font-mono text-[10px] uppercase tracking-widest bg-muted/50 border-muted"
					>MongoDB</Badge
				>
			</div>

			<p class="text-lg md:text-xl text-muted-foreground max-w-2xl leading-relaxed">
				{t('landing.tagline')}
			</p>
		</header>

		<div class="grid grid-cols-1 md:grid-cols-3 gap-6 w-full mt-8">
			<Card
				class="bg-card/50 backdrop-blur-sm border-muted transition-colors hover:border-primary/50 text-left"
			>
				<CardHeader>
					<Zap class="w-10 h-10 text-primary mb-4" strokeWidth={1.5} />
					<CardTitle class="text-lg">{t('landing.features.fast.title')}</CardTitle>
				</CardHeader>
				<CardContent>
					<p class="text-sm text-muted-foreground leading-relaxed">
						{t('landing.features.fast.desc')}
					</p>
				</CardContent>
			</Card>

			<Card
				class="bg-card/50 backdrop-blur-sm border-muted transition-colors hover:border-primary/50 text-left"
			>
				<CardHeader>
					<Shield class="w-10 h-10 text-primary mb-4" strokeWidth={1.5} />
					<CardTitle class="text-lg">{t('landing.features.secure.title')}</CardTitle>
				</CardHeader>
				<CardContent>
					<p class="text-sm text-muted-foreground leading-relaxed">
						{t('landing.features.secure.desc')}
					</p>
				</CardContent>
			</Card>

			<Card
				class="bg-card/50 backdrop-blur-sm border-muted transition-colors hover:border-primary/50 text-left"
			>
				<CardHeader>
					<Sparkles class="w-10 h-10 text-primary mb-4" strokeWidth={1.5} />
					<CardTitle class="text-lg">{t('landing.features.modern.title')}</CardTitle>
				</CardHeader>
				<CardContent>
					<p class="text-sm text-muted-foreground leading-relaxed">
						{t('landing.features.modern.desc')}
					</p>
				</CardContent>
			</Card>
		</div>
	</div>
</div>
