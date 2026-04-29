<script lang="ts">
	import { toastStore } from '$lib/stores/toast.svelte';
	import { flip } from 'svelte/animate';
	import { fly } from 'svelte/transition';

	const items = $derived(toastStore.items);
</script>

<div class="toast-container">
	{#each items as toast (toast.id)}
		<div
			class="toast-item {toast.type}"
			animate:flip={{ duration: 300 }}
			in:fly={{ x: 100, duration: 400 }}
			out:fly={{ x: 100, duration: 300 }}
		>
			<div class="icon">
				{#if toast.type === 'success'}
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<polyline points="20 6 9 17 4 12" />
					</svg>
				{:else}
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line
							x1="12"
							y1="16"
							x2="12.01"
							y2="16"
						/>
					</svg>
				{/if}
			</div>
			<div class="message">{toast.message}</div>
			<button class="close" onclick={() => toastStore.remove(toast.id)} aria-label="Close">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
				</svg>
			</button>
		</div>
	{/each}
</div>

<style>
	.toast-container {
		position: fixed;
		bottom: var(--space-lg);
		right: var(--space-lg);
		display: flex;
		flex-direction: column;
		gap: var(--space-sm);
		z-index: 10000;
		pointer-events: none;
	}

	.toast-item {
		pointer-events: auto;
		display: flex;
		align-items: center;
		gap: var(--space-md);
		min-width: 280px;
		max-width: 400px;
		padding: var(--space-md);
		border-radius: 12px;
		background: var(--glass-bg);
		backdrop-filter: blur(12px);
		border: 1px solid var(--glass-border);
		box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
		color: white;
	}

	.toast-item.success {
		border-left: 4px solid var(--success);
	}
	.toast-item.error {
		border-left: 4px solid var(--error);
	}
	.toast-item.warning {
		border-left: 4px solid var(--warning);
	}
	.toast-item.info {
		border-left: 4px solid var(--primary);
	}

	.icon {
		width: 20px;
		height: 20px;
		flex-shrink: 0;
	}

	.success .icon {
		color: var(--success);
	}
	.error .icon {
		color: var(--error);
	}

	.message {
		flex: 1;
		font-size: 0.9rem;
		font-weight: 500;
	}

	.close {
		opacity: 0.5;
		cursor: pointer;
		transition: opacity 0.2s;
		width: 16px;
		height: 16px;
	}

	.close:hover {
		opacity: 1;
	}
</style>
