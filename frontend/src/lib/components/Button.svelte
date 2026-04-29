<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		type?: 'button' | 'submit' | 'reset';
		variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'google' | 'github';
		size?: 'sm' | 'md' | 'lg';
		disabled?: boolean;
		full?: boolean;
		loading?: boolean;
		onclick?: (e: MouseEvent) => void;
		children?: Snippet;
		[key: string]: any;
	}

	// svelte-ignore custom_element_props_identifier
	let {
		type = 'button',
		variant = 'primary',
		size = 'md',
		disabled = false,
		full = false,
		loading = false,
		onclick,
		children,
		...rest
	}: Props = $props();
</script>

<button
	{type}
	class="btn btn-{variant} btn-{size} {full ? 'w-full' : ''} {loading
		? 'loading'
		: ''} {rest.class || ''}"
	{disabled}
	{onclick}
	{...rest}
>
	{#if loading}
		<span class="spinner"></span>
	{/if}
	{@render children?.()}
</button>

<style>
	.btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		border-radius: 12px;
		font-weight: 700;
		transition: all 0.3s ease;
		gap: 0.75rem;
		position: relative;
		overflow: hidden;
		border: none;
		cursor: pointer;
		letter-spacing: 0.02em;
		text-transform: uppercase;
	}

	.btn-sm {
		padding: 0.5rem 1.25rem;
		font-size: 0.8rem;
	}

	.btn-md {
		padding: 15px 20px;
		font-size: 0.95rem;
	}

	.btn-lg {
		padding: 1.1rem 2rem;
		font-size: 1rem;
	}

	.btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
		filter: grayscale(0.4);
	}

	.w-full {
		width: 100%;
		display: flex;
	}

	/* Variants */
	.btn-primary {
		background: linear-gradient(135deg, var(--primary, #00f2ea) 0%, #00c2bb 100%);
		color: #ffffff;
		font-weight: 800;
	}
	.btn-primary:hover:not(:disabled) {
		transform: translateY(-2px);
		box-shadow: 0 10px 30px var(--primary-glow, rgba(0, 242, 234, 0.3));
	}
	.btn-primary:active {
		transform: scale(0.98);
	}

	.btn-secondary {
		background: rgba(255, 255, 255, 0.05);
		border: 1px solid var(--glass-border, rgba(255, 255, 255, 0.08));
		color: var(--ghost-white, #f8f9fa);
		font-weight: 600;
	}
	.btn-secondary:hover:not(:disabled) {
		background: rgba(255, 255, 255, 0.08);
		border-color: rgba(255, 255, 255, 0.15);
	}

	.btn-outline {
		background: transparent;
		border: 1px solid var(--glass-border, rgba(255, 255, 255, 0.08));
		color: var(--ghost-white, #f8f9fa);
		font-weight: 600;
	}
	.btn-outline:hover:not(:disabled) {
		background: rgba(255, 255, 255, 0.05);
		border-color: var(--primary, #00f2ea);
	}

	.btn-ghost {
		background: transparent;
		color: var(--text-muted, rgba(248, 249, 250, 0.6));
		font-weight: 500;
		text-transform: none;
	}
	.btn-ghost:hover:not(:disabled) {
		background: rgba(255, 255, 255, 0.05);
		color: var(--ghost-white, #f8f9fa);
	}

	/* Social Buttons */
	.btn-google {
		background: white;
		color: #1a1a1a;
		text-transform: none;
		font-weight: 600;
	}
	.btn-google:hover:not(:disabled) {
		background: #f1f1f1;
		transform: translateY(-2px);
	}

	.btn-github {
		background: #24292e;
		color: white;
		text-transform: none;
		font-weight: 600;
	}
	.btn-github:hover:not(:disabled) {
		background: #2f363d;
		transform: translateY(-2px);
	}

	/* Loading Spinner */
	.spinner {
		width: 1rem;
		height: 1rem;
		border: 2px solid currentColor;
		border-right-color: transparent;
		border-radius: 50%;
		animation: spin 0.75s linear infinite;
	}
	@keyframes spin {
		100% {
			transform: rotate(360deg);
		}
	}
</style>
