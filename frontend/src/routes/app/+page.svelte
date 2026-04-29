<script lang="ts">
	import { onMount } from 'svelte';
	import { authStore, apiKeysStore, addToast } from '$lib/stores';
	import type { User } from '$lib/types';
	import { fade, fly } from 'svelte/transition';
	import { goto } from '$app/navigation';
	import { useTranslation } from '$lib/i18n/useTranslation';
	import LanguageSwitcher from '$lib/components/common/LanguageSwitcher.svelte';
	import SEO from '$lib/components/common/SEO.svelte';
	import LoadingBar from '$lib/components/common/LoadingBar.svelte';
	import EmptyState from '$lib/components/common/EmptyState.svelte';
	import { copyToClipboard } from '$lib/utils/clipboard';

	const { t } = useTranslation();

	let user = $state<User | null>(null);
	let loading = $state(true);
	let hoveredKey = $state(false);

	// Derived states from store for cleaner UI
	let currentApiKey = $derived(apiKeysStore.currentKey);
	let keyLoading = $derived(apiKeysStore.isLoading);

	onMount(() => {
		loadData();
	});

	async function loadData() {
		try {
			user = await authStore.getProfile();
		} catch (_e) {
			user = null;
			goto('/login');
		} finally {
			loading = false;
		}
	}

	async function handleLogout() {
		await authStore.logout();
		apiKeysStore.clear(); // Clear keys on logout
		window.location.href = '/login';
	}

	async function generateApiKey() {
		try {
			await apiKeysStore.create();
			addToast(t('dashboard.gen_success'), 'success');
		} catch (_e: any) {
			addToast(apiKeysStore.error, 'error');
		}
	}

	async function revokeApiKey() {
		if (!confirm(t('dashboard.revoke_confirm'))) return;

		try {
			await apiKeysStore.revoke();
			addToast(t('dashboard.revoked'), 'info');
		} catch (_e: any) {
			addToast(apiKeysStore.error, 'error');
		}
	}
</script>

<div class="page-container">
	<SEO title="FASMO | {t('dashboard.title')}" />
	{#if loading}
		<LoadingBar />
		<div class="loader-container" in:fade>
			<div class="spinner"></div>
			<p>Initializing...</p>
		</div>
	{:else}
		<div class="content" in:fly={{ y: 20, duration: 1000 }}>
			{#if user}
				<!-- DASHBOARD VIEW -->
				<header class="dashboard-header">
					<div class="header-text">
						<h1>{t('dashboard.title')}</h1>
						<p class="subtitle text-text-muted text-sm">
							{t('dashboard.system_status')}:
							<span class="status-online">{t('dashboard.active')}</span>
						</p>
					</div>
					<div class="header-actions flex items-center gap-4">
						<LanguageSwitcher />
						<button class="logout-btn" onclick={handleLogout}>{t('common.logout')}</button>
					</div>
				</header>

				<div class="dashboard-grid">
					<!-- Profile Card -->
					<div class="glass-pane card profile-card">
						<div class="card-icon">
							<svg viewBox="0 0 24 24" fill="none" class="icon-svg">
								<path
									d="M20 21C20 19.6044 20 18.9067 19.8278 18.3389C19.44 17.0605 18.4395 16.06 17.1611 15.6722C16.5933 15.5 15.8956 15.5 14.5 15.5H9.5C8.10444 15.5 7.40665 15.5 6.83886 15.6722C5.56045 16.06 4.56004 17.0605 4.17224 18.3389C4 18.9067 4 19.6044 4 21M16.5 7.5C16.5 9.98528 14.4853 12 12 12C9.51472 12 7.5 9.98528 7.5 7.5C7.5 5.01472 9.51472 3 12 3C14.4853 3 16.5 5.01472 16.5 7.5Z"
									stroke="currentColor"
									stroke-width="2"
									stroke-linecap="round"
									stroke-linejoin="round"
								/>
							</svg>
						</div>
						<div class="profile-info">
							<h2>{user.name}</h2>
							<p class="username">@{user.username}</p>
						</div>
					</div>

					<!-- API Key Card -->
					<div class="glass-pane card api-card">
						<div class="card-header">
							<h3>{t('dashboard.api_access')}</h3>
							<div class="status-badge {currentApiKey ? 'active' : 'inactive'}">
								{currentApiKey ? t('dashboard.active_status') : t('dashboard.inactive_status')}
							</div>
						</div>

						<div class="card-body">
							{#if currentApiKey}
								<div
									class="key-display"
									onmouseenter={() => (hoveredKey = true)}
									onmouseleave={() => (hoveredKey = false)}
									role="group"
								>
									<div class="key-value" class:blurred={!hoveredKey}>
										{currentApiKey}
									</div>
									<div class="key-actions">
										<button
											class="icon-btn"
											onclick={() => copyToClipboard(currentApiKey, 'API Key')}
											title={t('dashboard.copy')}
										>
											{t('dashboard.copy')}
										</button>
										<button class="icon-btn danger" onclick={revokeApiKey} disabled={keyLoading}
											>{t('dashboard.revoke')}</button
										>
									</div>
								</div>
								<p class="helper-text">{t('dashboard.hover_to_view')}</p>
							{:else}
								<EmptyState
									title={t('dashboard.no_key')}
									message="You don't have an active frequency key. Generate one to start transmission."
									icon="<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect width='18' height='11' x='3' y='11' rx='2' ry='2'/><path d='M7 11V7a5 5 0 0 1 10 0v4'/></svg>"
								/>
								<button class="cta-button" onclick={generateApiKey} disabled={keyLoading}>
									{#if keyLoading}
										{t('dashboard.generating')}
									{:else}
										{t('dashboard.generate_key')}
									{/if}
								</button>
							{/if}
						</div>
					</div>
				</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.page-container {
		min-height: 100vh;
		padding: var(--space-lg);
		display: flex;
		flex-direction: column;
		align-items: center;
		color: var(--ghost-white);
	}

	.loader-container {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 1rem;
		margin-top: 40vh;
		color: var(--text-muted);
	}

	.spinner {
		width: 40px;
		height: 40px;
		border: 3px solid rgba(255, 255, 255, 0.1);
		border-radius: 50%;
		border-top-color: var(--primary);
		animation: spin 1s ease-in-out infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

	.content {
		width: 100%;
		max-width: 1000px;
		margin: 0 auto;
	}

	/* Dashboard Styles */
	.dashboard-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-end;
		margin-bottom: var(--space-xl);
		padding-bottom: var(--space-md);
		border-bottom: 1px solid rgba(255, 255, 255, 0.1);
	}

	.header-text h1 {
		font-size: 2.5rem;
		margin: 0;
		background: linear-gradient(135deg, #fff 0%, rgba(255, 255, 255, 0.7) 100%);
		background-clip: text;
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
	}

	.subtitle {
		color: var(--text-muted);
		font-size: 0.9rem;
		margin-top: 4px;
	}

	.status-online {
		color: var(--success);
		font-weight: bold;
		text-shadow: 0 0 10px rgba(0, 255, 157, 0.3);
	}

	.logout-btn {
		background: transparent;
		border: 1px solid var(--glass-border);
		color: var(--text-muted);
		padding: 8px 16px;
		border-radius: 8px;
		transition: all 0.2s;
	}

	.logout-btn:hover {
		color: var(--error);
		border-color: var(--error);
		background: rgba(255, 77, 77, 0.05);
	}

	.dashboard-grid {
		display: grid;
		grid-template-columns: 1fr;
		gap: var(--space-lg);
	}

	@media (min-width: 768px) {
		.dashboard-grid {
			grid-template-columns: 1fr 1.5fr;
		}
	}

	.card {
		padding: var(--space-lg);
		border-radius: 20px;
	}

	/* Profile Card */
	.profile-card {
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: var(--space-md);
	}

	.card-icon {
		width: 80px;
		height: 80px;
		background: rgba(255, 255, 255, 0.05);
		border-radius: 50%;
		display: flex;
		align-items: center;
		justify-content: center;
		border: 1px solid var(--glass-border);
		color: var(--primary);
	}

	.icon-svg {
		width: 40px;
		height: 40px;
	}

	.profile-info h2 {
		font-size: 1.5rem;
		margin: 0;
	}

	.username {
		color: var(--text-muted);
		font-family: monospace;
		margin-top: 4px;
	}

	/* API Card */
	.api-card {
		display: flex;
		flex-direction: column;
	}

	.card-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: var(--space-lg);
	}

	.card-header h3 {
		font-size: 1.2rem;
		font-weight: 600;
		color: var(--ghost-white);
		margin: 0;
	}

	.status-badge {
		font-size: 0.75rem;
		padding: 4px 8px;
		border-radius: 4px;
		font-weight: bold;
		letter-spacing: 0.05em;
	}

	.status-badge.active {
		background: rgba(0, 255, 157, 0.1);
		color: var(--success);
		border: 1px solid rgba(0, 255, 157, 0.2);
	}

	.status-badge.inactive {
		background: rgba(255, 255, 255, 0.05);
		color: var(--text-muted);
	}

	.card-body {
		flex: 1;
		display: flex;
		flex-direction: column;
		justify-content: center;
	}

	.key-display {
		background: rgba(0, 0, 0, 0.3);
		border-radius: 12px;
		padding: 16px;
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 16px;
		border: 1px solid var(--glass-border);
		margin-bottom: 8px;
	}

	.key-value {
		font-family: monospace;
		font-size: 1.1rem;
		color: var(--primary);
		word-break: break-all;
		transition: all 0.3s ease;
	}

	.blurred {
		filter: blur(8px);
		opacity: 0.5;
		user-select: none;
	}

	.key-actions {
		display: flex;
		gap: 8px;
	}

	.icon-btn {
		background: rgba(255, 255, 255, 0.1);
		border: none;
		color: var(--ghost-white);
		padding: 6px 12px;
		border-radius: 6px;
		font-size: 0.8rem;
		cursor: pointer;
		transition: all 0.2s;
	}

	.icon-btn:hover {
		background: rgba(255, 255, 255, 0.2);
	}

	.icon-btn.danger {
		background: rgba(255, 77, 77, 0.1);
		color: var(--error);
	}

	.icon-btn.danger:hover {
		background: rgba(255, 77, 77, 0.2);
	}

	.helper-text {
		font-size: 0.8rem;
		color: var(--text-muted);
		text-align: center;
		margin-top: 8px;
	}

	.cta-button {
		width: 100%;
		padding: 14px;
		border-radius: 12px;
		background: linear-gradient(135deg, var(--primary) 0%, #00c2bb 100%);
		color: #ffffff; /* Changed from #000 */
		font-weight: 800;
		text-transform: uppercase;
		font-size: 0.9rem;
		letter-spacing: 0.05em;
		transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
		text-align: center;
		border: none;
		cursor: pointer;
	}

	.cta-button:hover:not(:disabled) {
		transform: translateY(-2px);
		box-shadow: 0 10px 20px rgba(0, 242, 234, 0.3);
	}
</style>
