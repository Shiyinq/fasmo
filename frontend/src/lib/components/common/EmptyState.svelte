<script lang="ts">
	interface Props {
		title: string;
		message: string;
		icon?: string;
	}

	let { title, message, icon }: Props = $props();
</script>

<div class="empty-state">
	{#if icon}
		<div class="icon-container">
			<!-- eslint-disable-next-line svelte/no-at-html-tags -->
			{@html icon}
		</div>
	{/if}
	<h3>{title}</h3>
	<p>{message}</p>
</div>

<style>
	.empty-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: var(--space-xl) var(--space-lg);
		text-align: center;
		color: var(--text-muted);
	}

	.icon-container {
		width: 64px;
		height: 64px;
		margin-bottom: var(--space-md);
		opacity: 0.5;
		color: var(--primary);
	}

	h3 {
		margin-bottom: 8px;
		font-size: 1.25rem;
	}

	p {
		max-width: 300px;
		font-size: 0.9rem;
	}
</style>
