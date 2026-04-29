<script lang="ts">
	interface Props {
		label?: string;
		type?: string;
		value?: string;
		placeholder?: string;
		error?: string;
		id?: string;
		oninput?: (e: Event & { currentTarget: EventTarget & HTMLInputElement }) => void;
		onblur?: (e: FocusEvent) => void;
		[key: string]: any;
	}

	// svelte-ignore custom_element_props_identifier
	let {
		label = '',
		type = 'text',
		value = $bindable(''),
		placeholder = '',
		error = '',
		id = Math.random().toString(36).substring(2, 11),
		oninput,
		onblur,
		...rest
	}: Props = $props();
</script>

<div class="input-group">
	{#if label}
		<label for={id} class="input-label">{label}</label>
	{/if}

	<input
		{id}
		{type}
		{placeholder}
		bind:value
		class="input-field {error ? 'has-error' : ''} {rest.class || ''}"
		{oninput}
		{onblur}
		{...rest}
	/>

	{#if error}
		<div class="error-msg">{error}</div>
	{/if}
</div>

<style>
	.input-group {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
		width: 100%;
		margin-bottom: 1rem;
	}

	.input-label {
		font-size: 0.875rem;
		font-weight: 600;
		color: var(--ghost-white, #f8f9fa);
		transition: color 0.2s;
	}

	.input-field {
		width: 100%;
		background: rgba(255, 255, 255, 0.03);
		border: 1px solid var(--glass-border, rgba(255, 255, 255, 0.08));
		border-radius: 12px;
		padding: 15px 20px;
		color: var(--ghost-white, #f8f9fa);
		font-family: var(--font-body, 'Inter', sans-serif);
		font-size: 1rem;
		transition: all 0.3s ease;
		outline: none;
	}

	.input-field:focus {
		border-color: var(--primary, #00f2ea);
		box-shadow: 0 0 20px rgba(0, 242, 234, 0.1);
		background: rgba(255, 255, 255, 0.05);
	}

	.input-field::placeholder {
		color: rgba(255, 255, 255, 0.25);
	}

	.has-error {
		border-color: var(--error, #ff4d4d);
	}
	.has-error:focus {
		box-shadow: 0 0 15px rgba(255, 77, 77, 0.15);
	}

	.error-msg {
		font-size: 0.75rem;
		color: var(--error, #ff4d4d);
		margin-top: 0.25rem;
		animation: slideDown 0.2s ease-out;
	}

	@keyframes slideDown {
		from {
			opacity: 0;
			transform: translateY(-5px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}
</style>
