<script lang="ts">
	import { useTranslation } from '$lib/i18n/useTranslation';
	import { fade } from 'svelte/transition';

	const { locale, changeLocale, availableLocales } = useTranslation();

	let isOpen = $state(false);

	function toggleDropdown() {
		isOpen = !isOpen;
	}

	function selectLocale(code: any) {
		changeLocale(code);
		isOpen = false;
	}
</script>

<div class="lang-switcher">
	<button class="current-lang" onclick={toggleDropdown} aria-label="Change Language">
		<span class="flag">{availableLocales.find((l) => l.code === locale.value)?.flag}</span>
		<span class="code">{locale.value.toUpperCase()}</span>
		<svg
			class="chevron {isOpen ? 'open' : ''}"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			stroke-width="2"
		>
			<path d="M6 9l6 6 6-6" />
		</svg>
	</button>

	{#if isOpen}
		<div class="dropdown glass-pane" transition:fade={{ duration: 150 }}>
			{#each availableLocales as loc}
				<button
					class="lang-option {locale.value === loc.code ? 'active' : ''}"
					onclick={() => selectLocale(loc.code)}
				>
					<span class="flag">{loc.flag}</span>
					<span class="name">{loc.nativeName}</span>
					{#if locale.value === loc.code}
						<span class="check">✓</span>
					{/if}
				</button>
			{/each}
		</div>
	{/if}
</div>

{#if isOpen}
	<button class="overlay" onclick={() => (isOpen = false)} aria-label="Close menu"></button>
{/if}

<style>
	.lang-switcher {
		position: relative;
		display: inline-block;
		z-index: 101;
	}

	.current-lang {
		display: flex;
		align-items: center;
		gap: 8px;
		background: rgba(255, 255, 255, 0.05);
		border: 1px solid var(--glass-border);
		padding: 6px 12px;
		border-radius: 10px;
		color: var(--ghost-white);
		font-size: 0.85rem;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.2s;
	}

	.current-lang:hover {
		background: rgba(255, 255, 255, 0.1);
		border-color: var(--primary);
	}

	.chevron {
		width: 14px;
		height: 14px;
		transition: transform 0.3s var(--ease-smooth);
	}

	.chevron.open {
		transform: rotate(180deg);
	}

	.dropdown {
		position: absolute;
		top: calc(100% + 8px);
		right: 0;
		min-width: 180px;
		padding: 8px;
		border-radius: 12px;
		display: flex;
		flex-direction: column;
		gap: 4px;
		box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
	}

	.lang-option {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 10px 12px;
		border-radius: 8px;
		color: var(--text-muted);
		font-size: 0.9rem;
		cursor: pointer;
		transition: all 0.2s;
		text-align: left;
		background: transparent;
		border: none;
		width: 100%;
	}

	.lang-option:hover {
		background: rgba(255, 255, 255, 0.05);
		color: var(--ghost-white);
	}

	.lang-option.active {
		background: rgba(0, 242, 234, 0.1);
		color: var(--primary);
	}

	.check {
		margin-left: auto;
		font-weight: bold;
	}

	.overlay {
		position: fixed;
		top: 0;
		left: 0;
		width: 100vw;
		height: 100vh;
		background: transparent;
		z-index: 100;
		border: none;
	}

	.flag {
		font-size: 1.1rem;
	}
</style>
