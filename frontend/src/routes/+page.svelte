<script lang="ts">
	import { fly } from 'svelte/transition';
	import { useTranslation } from '$lib/i18n/useTranslation';
	import LanguageSwitcher from '$lib/components/common/LanguageSwitcher.svelte';
	import SEO from '$lib/components/common/SEO.svelte';

	const { t } = useTranslation();
</script>

<SEO title="FASMO | {t('landing.hero')}" description={t('landing.tagline')} />

<div
	class="landing-container min-h-screen flex flex-col items-center justify-center text-center overflow-hidden"
>
	<nav
		class="top-nav absolute top-0 right-0 w-full flex justify-end items-center gap-6 z-10 p-4 md:p-6"
	>
		<LanguageSwitcher />
		<a
			href="/login"
			class="nav-link text-ghost-white font-semibold text-sm opacity-80 transition-opacity hover:opacity-100 hover:text-primary"
			>{t('common.login')}</a
		>
		<a
			href="/register"
			class="nav-btn border border-glass-border px-7 py-2 rounded-full text-ghost-white font-semibold text-[0.75rem] uppercase tracking-wider transition-all hover:bg-primary hover:text-void hover:border-primary"
			>{t('common.register')}</a
		>
	</nav>

	<div
		class="content max-w-7xl w-full flex flex-col items-center justify-center gap-[3vh]"
		in:fly={{ y: 20, duration: 1000 }}
	>
		<header class="hero-section flex flex-col items-center gap-[2vh] w-full">
			<pre class="ascii-logo font-bold leading-tight whitespace-pre m-0 select-none text-center">
		('-.      .-')   _   .-')                
	   ( OO ).-. ( OO ).( '.( OO )_              
26: ,------./ . --. /(_)---\_),--.   ,--.).-'),-----. 
27: ('-| _.---'| \-.  \ /    _ | |   `.'   |( OO'  .-.  '
28: (OO|(_\  .-'-'  |  |\  :` `. |         |/   |  | |  |
29: /  |  '--.\| |_.'  | '..`''.)|  |'.'|  |\_) |  |\|  |
30: \_)|  .--' |  .-.  |.-._)   \|  |   |  |  \ |  | |  |
31:   \|  |_)  |  | |  |\       /|  |   |  |   `'  '-'  '
32:    `--'    `--' `--' `-----' `--'   `--'     `-----' 
			</pre>
			<div
				class="pill text-[0.75rem] uppercase tracking-[0.25em] px-5 py-2 rounded-full bg-black/40 border border-white/10 text-ghost-white mb-[2vh] backdrop-blur-md shadow-2xl flex gap-3 items-center font-semibold"
			>
				<span>FastAPI</span>
				<span class="accent text-primary">•</span>
				<span>SvelteKit</span>
				<span class="accent text-primary">•</span>
				<span>MongoDB</span>
			</div>
			<p class="tagline text-ghost-white leading-relaxed font-light tracking-tight max-w-[800px]">
				{t('landing.tagline')}
			</p>

			<div class="h-[4vh]"></div>
		</header>

		<div class="features-grid grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-[1000px]">
			<div
				class="feature-card glass-card group p-6 text-left transition-all hover:-translate-y-1 hover:border-primary"
			>
				<div class="icon-wrapper w-[60px] h-[60px] mb-4 flex items-center justify-center">
					<img
						src="/assets/icons/lightning.png"
						alt="Fast"
						class="feature-icon w-full h-full object-contain filter drop-shadow-[0_0_10px_rgba(255,255,255,0.2)]"
					/>
				</div>
				<h3 class="text-[1.1rem] mb-2 text-ghost-white">{t('landing.features.fast.title')}</h3>
				<p class="text-text-muted leading-tight text-sm">{t('landing.features.fast.desc')}</p>
			</div>
			<div
				class="feature-card glass-card group p-6 text-left transition-all hover:-translate-y-1 hover:border-primary"
			>
				<div class="icon-wrapper w-[60px] h-[60px] mb-4 flex items-center justify-center">
					<img
						src="/assets/icons/padlock.png"
						alt="Secure"
						class="feature-icon w-full h-full object-contain filter drop-shadow-[0_0_10px_rgba(255,255,255,0.2)]"
					/>
				</div>
				<h3 class="text-[1.1rem] mb-2 text-ghost-white">{t('landing.features.secure.title')}</h3>
				<p class="text-text-muted leading-tight text-sm">{t('landing.features.secure.desc')}</p>
			</div>
			<div
				class="feature-card glass-card group p-6 text-left transition-all hover:-translate-y-1 hover:border-primary"
			>
				<div class="icon-wrapper w-[60px] h-[60px] mb-4 flex items-center justify-center">
					<img
						src="/assets/icons/diamond.png"
						alt="Modern"
						class="feature-icon w-full h-full object-contain filter drop-shadow-[0_0_10px_rgba(255,255,255,0.2)]"
					/>
				</div>
				<h3 class="text-[1.1rem] mb-2 text-ghost-white">{t('landing.features.modern.title')}</h3>
				<p class="text-text-muted leading-tight text-sm">{t('landing.features.modern.desc')}</p>
			</div>
		</div>
	</div>
</div>

<style>
	.landing-container {
		padding: var(--space-md);
	}

	.ascii-logo {
		font-family: 'Courier New', Courier, monospace;
		font-size: clamp(16px, 2.8vh, 28px);
		padding-top: 1vh;
		padding-bottom: 1vh;
		filter: drop-shadow(0 0 10px rgba(255, 255, 255, 0.15));
		background: linear-gradient(135deg, #fff 0%, rgba(255, 255, 255, 0.8) 100%);
		-webkit-background-clip: text;
		background-clip: text;
		-webkit-text-fill-color: transparent;
	}

	.pill .accent {
		text-shadow: 0 0 10px var(--color-primary);
	}

	.tagline {
		font-size: clamp(1.2rem, 3.5vw, 1.8rem);
	}

	.nav-btn {
		background: rgba(255, 255, 255, 0.1);
		box-shadow: 0 0 20px rgba(0, 255, 255, 0.3);
	}

	.feature-card {
		box-shadow:
			0 10px 30px rgba(0, 0, 0, 0.2),
			0 0 20px rgba(0, 242, 234, 0.1);
	}
</style>
