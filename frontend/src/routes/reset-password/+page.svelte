<script lang="ts">
	import { page } from '$app/stores';
	import { authStore } from '$lib/stores';
	import { addToast } from '$lib/stores';
	import { onMount } from 'svelte';
	import { fade, fly, slide } from 'svelte/transition';
	import { useTranslation } from '$lib/i18n/useTranslation';

	const { t } = useTranslation();

	let newPassword = $state('');
	let confirmPassword = $state('');
	// Using global store states (SDD)
	let loading = $derived(authStore.isLoading);
	let error = $derived(authStore.error);
	let success = $state(false);
	let token = $state('');
	let showPassword = $state(false);

	// Requirements Checklist
	let reqLength = $derived(newPassword.length > 7);
	let reqNumber = $derived(/[0-9]/.test(newPassword));
	let reqSpecial = $derived(/[^A-Za-z0-9]/.test(newPassword));
	let reqMatch = $derived(newPassword.length > 0 && newPassword === confirmPassword);

	// Password Strength
	let passwordStrength = $derived(calculateStrength(newPassword));

	function calculateStrength(pw: string) {
		if (!pw) return 0;
		let score = 0;
		if (pw.length > 7) score++;
		if (/[A-Z]/.test(pw)) score++;
		if (/[0-9]/.test(pw)) score++;
		if (/[^A-Za-z0-9]/.test(pw)) score++;
		return score; // Max 4
	}

	function getStrengthLabel(score: number) {
		if (score === 0) return '';
		if (score < 2) return 'Weak';
		if (score < 4) return 'Good';
		return 'Strong';
	}

	function getStrengthColor(score: number) {
		if (score < 2) return 'var(--error)';
		if (score < 4) return 'var(--warning)';
		return 'var(--success)';
	}

	let allValid = $derived(reqLength && reqNumber && reqSpecial && reqMatch);

	onMount(() => {
		token = $page.url.searchParams.get('token') || '';
		if (!token) {
			error = 'Invalid frequency token.';
		}
	});

	async function handleSubmit() {
		if (!token) {
			error = 'Signal lost. No token.';
			return;
		}

		if (!allValid) {
			error = 'Please satisfy all security requirements.';
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
			console.error(e);
			addToast(authStore.error, 'error');
		}
	}
</script>

<svelte:head>
	<title>FASMO | {t('auth.reset_password')}</title>
	<meta name="robots" content="noindex, nofollow" />
</svelte:head>

<div class="page-container">
	<div class="content">
		<!-- Visual Section -->
		<div class="visual-pane" in:fly={{ y: 20, duration: 1000, delay: 200 }}>
			<div class="header-section">
				<h1>SECURE</h1>
				<p class="subtitle">{t('auth.reset_password_subtitle')}</p>
			</div>

			<div class="asset-wrapper">
				<img
					src="/assets/background/reset-password.png"
					alt="Lock"
					class="accent-asset {allValid ? 'unlocked' : ''}"
				/>
			</div>
		</div>

		<!-- Interaction Section -->
		<div class="interaction-pane glass-pane" in:fly={{ y: 50, duration: 1000 }}>
			{#if success}
				<div class="success-state" in:fade>
					<div class="success-icon">
						<svg viewBox="0 0 24 24" fill="none" class="check-svg">
							<path
								d="M20 6L9 17L4 12"
								stroke="currentColor"
								stroke-width="2"
								stroke-linecap="round"
								stroke-linejoin="round"
							/>
						</svg>
					</div>
					<h2>{t('auth.reset_password')}</h2>
					<p class="success-desc">
						{t('auth.reset_success')}
					</p>
				</div>
			{:else}
				<form
					onsubmit={(e) => {
						e.preventDefault();
						handleSubmit();
					}}
					class="reset-form"
				>
					{#if error}
						<div class="error-banner" transition:fade>
							<span class="error-icon">!</span>
							{error}
						</div>
					{/if}

					<div class="input-group">
						<div class="label-row">
							<label for="new-password" class="input-label">{t('auth.new_password')}</label>
							<button
								type="button"
								class="toggle-btn"
								onclick={() => (showPassword = !showPassword)}
							>
								{showPassword ? t('common.cancel') : t('common.save')}
							</button>
						</div>
						<div class="input-wrapper">
							{#if showPassword}
								<input
									id="new-password"
									type="text"
									placeholder="New secure password"
									bind:value={newPassword}
									class="glass-input"
									required
								/>
							{:else}
								<input
									id="new-password"
									type="password"
									placeholder={t('auth.new_password')}
									bind:value={newPassword}
									class="glass-input"
									required
								/>
							{/if}
						</div>
					</div>

					<!-- Password Strength Meter -->
					{#if newPassword}
						<div class="strength-meter" transition:slide>
							<div class="strength-bars">
								<div
									class="bar"
									style="background: {passwordStrength >= 1
										? getStrengthColor(passwordStrength)
										: 'rgba(255,255,255,0.1)'}"
								></div>
								<div
									class="bar"
									style="background: {passwordStrength >= 2
										? getStrengthColor(passwordStrength)
										: 'rgba(255,255,255,0.1)'}"
								></div>
								<div
									class="bar"
									style="background: {passwordStrength >= 3
										? getStrengthColor(passwordStrength)
										: 'rgba(255,255,255,0.1)'}"
								></div>
								<div
									class="bar"
									style="background: {passwordStrength >= 4
										? getStrengthColor(passwordStrength)
										: 'rgba(255,255,255,0.1)'}"
								></div>
							</div>
							<span class="strength-label" style="color: {getStrengthColor(passwordStrength)}">
								{getStrengthLabel(passwordStrength)}
							</span>
						</div>
					{/if}

					<div class="input-group">
						<label for="confirm-password" class="input-label">{t('auth.confirm_password')}</label>
						<div class="input-wrapper">
							{#if showPassword}
								<input
									id="confirm-password"
									type="text"
									placeholder="Confirm new password"
									bind:value={confirmPassword}
									class="glass-input {reqMatch && confirmPassword ? 'valid' : ''}"
									required
								/>
							{:else}
								<input
									id="confirm-password"
									type="password"
									placeholder={t('auth.confirm_password')}
									bind:value={confirmPassword}
									class="glass-input {reqMatch && confirmPassword ? 'valid' : ''}"
									required
								/>
							{/if}
							{#if reqMatch && confirmPassword}
								<div class="check-indicator" in:fade>✓</div>
							{/if}
						</div>
					</div>

					<!-- Security Checklist -->
					<div class="checklist" transition:slide>
						<div class="check-item {reqLength ? 'met' : ''}">
							<span class="icon">{reqLength ? '✓' : '○'}</span>
							{t('auth.req_length')}
						</div>
						<div class="check-item {reqNumber ? 'met' : ''}">
							<span class="icon">{reqNumber ? '✓' : '○'}</span>
							{t('auth.req_number')}
						</div>
						<div class="check-item {reqSpecial ? 'met' : ''}">
							<span class="icon">{reqSpecial ? '✓' : '○'}</span>
							{t('auth.req_special')}
						</div>
						<div class="check-item {reqMatch ? 'met' : ''}">
							<span class="icon">{reqMatch ? '✓' : '○'}</span>
							{t('auth.req_match')}
						</div>
					</div>

					<div class="actions">
						<button type="submit" class="cta-button" disabled={loading || !allValid}>
							{#if loading}
								{t('auth.resetting')}
							{:else}
								{t('auth.reset_password').toUpperCase()}
							{/if}
						</button>

						<a href="/login" class="cancel-link">{t('common.cancel')}</a>
					</div>
				</form>
			{/if}
		</div>
	</div>
</div>

<style>
	.page-container {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-lg);
		position: relative;
	}

	.content {
		width: 100%;
		max-width: 1100px;
		display: grid;
		grid-template-columns: 1fr;
		gap: var(--space-xl);
		align-items: center;
	}

	@media (min-width: 1024px) {
		.content {
			grid-template-columns: 1fr 450px;
		}
	}

	/* Visual Pane */
	.visual-pane {
		display: flex;
		flex-direction: column;
		justify-content: center;
		position: relative;
		z-index: 1;
	}

	.header-section h1 {
		font-size: clamp(3rem, 6vw, 5rem);
		line-height: 0.9;
		margin-bottom: var(--space-md);
		color: var(--ghost-white);
	}

	.subtitle {
		font-size: 1.125rem;
		max-width: 400px;
		color: var(--text-muted);
		border-left: 2px solid var(--success);
		padding-left: var(--space-md);
	}

	.asset-wrapper {
		position: absolute;
		top: 50%;
		left: 50%;
		transform: translate(-50%, -50%);
		z-index: -1;
		width: 100%;
		height: 100%;
		pointer-events: none;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.accent-asset {
		width: 100%;
		max-width: 1050px;
		opacity: 0.9;
		transition: all 0.5s ease;
		filter: drop-shadow(0 0 40px rgba(0, 255, 157, 0.2));
	}

	/* Simple unlock animation state */
	.accent-asset.unlocked {
		filter: drop-shadow(0 0 60px rgba(0, 255, 157, 0.6));
		transform: scale(1.05);
	}

	/* Interaction Pane */
	.interaction-pane {
		padding: 48px;
		display: flex;
		flex-direction: column;
		position: relative;
		overflow: hidden;
		min-height: 450px;
		justify-content: center;
	}

	/* Add top accent line */
	.interaction-pane::before {
		content: '';
		position: absolute;
		top: 0;
		left: 0;
		width: 100%;
		height: 2px;
		background: linear-gradient(90deg, transparent, var(--success), transparent);
	}

	.reset-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-md);
	}

	.input-group {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	/* Strength Meter */
	.strength-meter {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-top: -4px;
		margin-bottom: 8px;
		gap: 10px;
	}

	.strength-bars {
		display: flex;
		gap: 4px;
		flex: 1;
	}

	.bar {
		height: 4px;
		border-radius: 2px;
		flex: 1;
		transition: background 0.3s ease;
	}

	.strength-label {
		font-size: 0.75rem;
		font-weight: 600;
		min-width: 40px;
		text-align: right;
	}

	.label-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.input-label {
		font-weight: 600;
		font-size: 0.95rem;
		color: var(--ghost-white);
	}

	.toggle-btn {
		font-size: 0.8rem;
		color: var(--success);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.input-wrapper {
		position: relative;
	}

	.glass-input {
		width: 100%;
		background: rgba(255, 255, 255, 0.03);
		border: 1px solid var(--glass-border);
		border-radius: 12px;
		padding: 16px 20px;
		color: var(--ghost-white);
		font-family: var(--font-body);
		font-size: 1rem;
		transition: all 0.3s var(--ease-smooth);
	}

	.glass-input.valid {
		border-color: var(--success);
	}

	.glass-input:focus {
		outline: none;
		border-color: var(--success);
		box-shadow: 0 0 15px rgba(0, 255, 157, 0.15);
		background: rgba(255, 255, 255, 0.05);
	}

	.check-indicator {
		position: absolute;
		right: 15px;
		top: 50%;
		transform: translateY(-50%);
		color: var(--success);
		font-weight: bold;
	}

	/* Checklist */
	.checklist {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 8px;
		margin-top: 4px;
	}

	.check-item {
		font-size: 0.8rem;
		color: var(--text-muted);
		display: flex;
		align-items: center;
		gap: 6px;
		transition: color 0.3s ease;
	}

	.check-item.met {
		color: var(--success);
	}

	.icon {
		font-weight: bold;
	}

	.actions {
		display: flex;
		flex-direction: column;
		gap: var(--space-md);
		margin-top: var(--space-sm);
		text-align: center;
	}

	.cta-button {
		width: 100%;
		padding: 16px;
		border-radius: 12px;
		background: linear-gradient(135deg, var(--success) 0%, #00bc72 100%);
		color: #000;
		font-weight: 700;
		font-size: 1rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		transition: all 0.3s var(--ease-elastic);
	}

	.cta-button:hover:not(:disabled) {
		transform: translateY(-2px);
		box-shadow: 0 10px 30px rgba(0, 255, 157, 0.3);
	}

	.cta-button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
		filter: grayscale(1);
	}

	.cancel-link {
		color: var(--text-muted);
		font-size: 0.9rem;
		transition: color 0.2s;
	}

	.cancel-link:hover {
		color: var(--ghost-white);
	}

	/* Success State */
	.success-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: var(--space-md);
	}

	.success-icon {
		width: 64px;
		height: 64px;
		background: rgba(0, 255, 157, 0.1);
		border-radius: 50%;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--success);
		margin-bottom: var(--space-sm);
	}

	.check-svg {
		width: 32px;
		height: 32px;
	}

	.success-desc {
		font-size: 1rem;
		color: var(--text-muted);
	}

	.error-banner {
		background: rgba(255, 77, 77, 0.1);
		border: 1px solid var(--error);
		padding: 12px;
		border-radius: 8px;
		color: #ff8888;
		font-size: 0.9rem;
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.error-icon {
		background: var(--error);
		color: black;
		width: 20px;
		height: 20px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 50%;
		font-weight: bold;
		font-size: 0.8rem;
	}
</style>
