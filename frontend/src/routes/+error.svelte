<script lang="ts">
	import { page } from '$app/stores';
	import { fly } from 'svelte/transition';
	import SEO from '$lib/components/common/SEO.svelte';
	import { useTranslation } from '$lib/i18n/useTranslation';
	import { Search, ServerCrash, ShieldAlert, WifiOff, Home, RefreshCw } from 'lucide-svelte';

	const { t } = useTranslation();

	function getErrorInfo(code: number) {
		switch (code) {
			case 404:
				return {
					title: t('errors.404.title'),
					subtitle: t('errors.404.subtitle'),
					description: t('errors.404.description'),
					icon: Search,
					color: 'var(--warning)'
				};
			case 500:
				return {
					title: t('errors.500.title'),
					subtitle: t('errors.500.subtitle'),
					description: t('errors.500.description'),
					icon: ServerCrash,
					color: 'var(--error)'
				};
			case 403:
				return {
					title: t('errors.403.title'),
					subtitle: t('errors.403.subtitle'),
					description: t('errors.403.description'),
					icon: ShieldAlert,
					color: 'var(--error)'
				};
			case 401:
				return {
					title: t('errors.401.title'),
					subtitle: t('errors.401.subtitle'),
					description: t('errors.401.description'),
					icon: ShieldAlert,
					color: 'var(--primary)'
				};
			default:
				return {
					title: t('errors.default.title'),
					subtitle: t('errors.default.subtitle'),
					description: t('errors.default.description'),
					icon: WifiOff,
					color: 'var(--text-muted)'
				};
		}
	}

	let status = $derived($page.status);
	let errorInfo = $derived(getErrorInfo(status));
</script>

<SEO title="FASMO | {status} - {errorInfo.title}" />

<div class="error-page" in:fly={{ y: 20, duration: 1000 }}>
	<div class="error-container glass-pane">
		<div class="icon-wrapper" style="--icon-color: {errorInfo.color}">
			<errorInfo.icon size={48} />
		</div>
		<div class="status">{status}</div>
		<h1>{errorInfo.title}</h1>
		<p class="subtitle">{errorInfo.subtitle}</p>
		<p class="description">{errorInfo.description}</p>

		{#if $page.error?.message && $page.error.message !== errorInfo.subtitle}
			<div class="debug-info">
				<code>{$page.error.message}</code>
			</div>
		{/if}

		<div class="actions">
			<a href="/" class="btn-primary">
				<Home size={18} />
				{t('errors.goHome')}
			</a>
			<button class="btn-outline" onclick={() => window.location.reload()}>
				<RefreshCw size={18} />
				{t('errors.tryAgain')}
			</button>
		</div>
	</div>
</div>

<style>
	.error-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-lg);
		background: radial-gradient(circle at center, #1a1a2e 0%, #0a0a0f 100%);
	}

	.error-container {
		max-width: 550px;
		width: 100%;
		padding: var(--space-xl);
		text-align: center;
		border-radius: 24px;
	}

	.icon-wrapper {
		width: 80px;
		height: 80px;
		margin: 0 auto var(--space-lg);
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--icon-color);
		background: rgba(255, 255, 255, 0.03);
		border-radius: 20px;
		border: 1px solid rgba(255, 255, 255, 0.1);
	}

	.status {
		font-size: 5rem;
		font-weight: 900;
		line-height: 1;
		background: linear-gradient(to bottom, var(--primary), transparent);
		-webkit-background-clip: text;
		background-clip: text;
		-webkit-text-fill-color: transparent;
		opacity: 0.3;
		margin-bottom: var(--space-sm);
	}

	h1 {
		font-size: 2rem;
		font-weight: 800;
		margin-bottom: var(--space-xs);
		color: var(--primary);
		letter-spacing: -0.02em;
	}

	.subtitle {
		font-size: 1.1rem;
		font-weight: 600;
		color: white;
		margin-bottom: var(--space-md);
	}

	.description {
		color: var(--text-muted);
		margin-bottom: var(--space-xl);
		line-height: 1.6;
		font-size: 0.95rem;
	}

	.debug-info {
		background: rgba(0, 0, 0, 0.3);
		padding: var(--space-sm) var(--space-md);
		border-radius: 12px;
		margin-bottom: var(--space-xl);
		border: 1px solid rgba(255, 255, 255, 0.05);
	}

	code {
		font-family: var(--font-mono);
		font-size: 0.8rem;
		color: var(--error);
		word-break: break-all;
	}

	.actions {
		display: flex;
		gap: var(--space-md);
		justify-content: center;
	}

	.btn-primary,
	.btn-outline {
		display: flex;
		align-items: center;
		gap: var(--space-sm);
		padding: var(--space-sm) var(--space-lg);
		border-radius: 99px;
		font-weight: 600;
		transition: all 0.2s;
		font-size: 0.95rem;
		cursor: pointer;
	}

	.btn-primary {
		background: var(--primary);
		color: white;
	}

	.btn-primary:hover {
		transform: translateY(-2px);
		box-shadow: 0 4px 15px var(--primary-glow);
	}

	.btn-outline {
		border: 1px solid var(--glass-border);
		color: white;
		background: transparent;
	}

	.btn-outline:hover {
		background: rgba(255, 255, 255, 0.05);
		transform: translateY(-1px);
	}

	@media (max-width: 480px) {
		.actions {
			flex-direction: column;
		}
		.btn-primary,
		.btn-outline {
			width: 100%;
			justify-content: center;
		}
	}
</style>
