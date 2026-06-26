<script lang="ts">
	import { onMount } from 'svelte';
	import { authStore, apiKeysStore, addToast } from '$lib/stores';
	import type { User } from '$lib/types';
	import { fade, slide } from 'svelte/transition';
	import { goto } from '$app/navigation';
	import { useTranslation } from '$lib/i18n/useTranslation';
	import LanguageSwitcher from '$lib/components/common/LanguageSwitcher.svelte';
	import ThemeToggle from '$lib/components/common/ThemeToggle.svelte';
	import SEO from '$lib/components/common/SEO.svelte';
	import EmptyState from '$lib/components/common/EmptyState.svelte';
	import { copyToClipboard } from '$lib/utils/clipboard';
	import {
		Card,
		CardHeader,
		CardTitle,
		CardContent,
		CardDescription
	} from '$lib/components/ui/card';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Avatar from '$lib/components/ui/avatar';
	import * as Breadcrumb from '$lib/components/ui/breadcrumb';
	import * as Tabs from '$lib/components/ui/tabs';
	import * as Alert from '$lib/components/ui/alert';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import { Badge } from '$lib/components/ui/badge';
	import { Separator } from '$lib/components/ui/separator';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { Button } from '$lib/components/ui/button';
	import {
		Key,
		Copy,
		Trash2,
		ShieldAlert,
		Loader2,
		LayoutDashboard,
		Activity,
		ShieldCheck,
		Zap,
		LogOut,
		ExternalLink
	} from 'lucide-svelte';

	const { t } = useTranslation();

	let user = $state<User | null>(null);
	let activeTab = $state('overview');
	let loading = $derived(authStore.isLoading);
	let hoveredKey = $state(false);
	let isRevokeDialogOpen = $state(false);

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
		}
	}

	async function handleLogout() {
		await authStore.logout();
		apiKeysStore.clear();
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
		isRevokeDialogOpen = false;
		try {
			await apiKeysStore.revoke();
			addToast(t('dashboard.revoked'), 'info');
		} catch (_e: any) {
			addToast(apiKeysStore.error, 'error');
		}
	}

	function getInitials(name: string) {
		return name
			.split(' ')
			.map((n) => n[0])
			.join('')
			.toUpperCase()
			.substring(0, 2);
	}
</script>

<SEO title="FASMO | {t('dashboard.title')}" />

<div class="flex min-h-screen flex-col bg-background">
	<!-- Header always visible -->
	<header
		class="sticky top-0 z-40 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60"
	>
		<div class="container flex h-16 items-center justify-between py-4">
			<div class="flex items-center gap-4">
				<div class="flex items-center gap-2 font-bold text-xl tracking-tight mr-4">
					<div class="bg-primary text-primary-foreground rounded-md p-1">
						<Activity class="w-5 h-5" />
					</div>
					FASMO
				</div>
				<Separator orientation="vertical" class="h-6 hidden md:block" />
				<Breadcrumb.Root class="hidden md:block">
					<Breadcrumb.List>
						<Breadcrumb.Item>
							<Breadcrumb.Link href="/">{t('common.home')}</Breadcrumb.Link>
						</Breadcrumb.Item>
						<Breadcrumb.Separator />
						<Breadcrumb.Item>
							<Breadcrumb.Page>{t('dashboard.title')}</Breadcrumb.Page>
						</Breadcrumb.Item>
					</Breadcrumb.List>
				</Breadcrumb.Root>
			</div>
			<div class="flex items-center gap-4">
				<LanguageSwitcher />
				<ThemeToggle />

				<DropdownMenu.Root>
					<DropdownMenu.Trigger>
						<Button
							variant="ghost"
							class="relative h-10 w-10 rounded-full p-0 overflow-hidden border border-border/50 hover:bg-muted/50"
						>
							<Avatar.Root class="h-full w-full">
								<Avatar.Fallback class="bg-primary text-primary-foreground text-xs font-bold">
									{user ? getInitials(user.name) : '??'}
								</Avatar.Fallback>
							</Avatar.Root>
						</Button>
					</DropdownMenu.Trigger>
					<DropdownMenu.Content class="w-56" align="end">
						<DropdownMenu.Label class="font-normal">
							<div class="flex flex-col space-y-1">
								<p class="text-sm font-medium leading-none">{user?.name}</p>
								<p class="text-xs leading-none text-muted-foreground">{user?.email}</p>
							</div>
						</DropdownMenu.Label>
						<DropdownMenu.Separator />
						<DropdownMenu.Group>
							<DropdownMenu.Item onclick={() => (activeTab = 'overview')}>
								{t('common.overview')}
							</DropdownMenu.Item>
							<DropdownMenu.Item onclick={() => (activeTab = 'api-access')}>
								{t('dashboard.api_access')}
							</DropdownMenu.Item>
							<DropdownMenu.Item disabled>
								{t('common.settings')}
							</DropdownMenu.Item>
						</DropdownMenu.Group>
						<DropdownMenu.Separator />
						<DropdownMenu.Item
							onclick={handleLogout}
							class="text-destructive focus:text-destructive"
						>
							<LogOut class="mr-2 h-4 w-4" />
							<span>{t('common.logout')}</span>
						</DropdownMenu.Item>
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			</div>
		</div>
	</header>

	{#if loading}
		<main class="flex-1 container pb-8 pt-36 space-y-12">
			<div class="flex items-center justify-between pt-4">
				<div class="space-y-2">
					<Skeleton class="h-8 w-[150px]" />
					<Skeleton class="h-4 w-[250px]" />
				</div>
			</div>

			<div class="space-y-4">
				<Skeleton class="h-10 w-[300px]" />
				<div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
					{#each Array(4) as _}
						<Card>
							<CardHeader class="pb-2">
								<Skeleton class="h-4 w-24" />
							</CardHeader>
							<CardContent>
								<Skeleton class="h-8 w-16 mb-1" />
								<Skeleton class="h-3 w-32" />
							</CardContent>
						</Card>
					{/each}
				</div>
				<div class="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
					<Skeleton class="h-[400px] lg:col-span-3 rounded-xl" />
					<Skeleton class="h-[400px] lg:col-span-4 rounded-xl" />
				</div>
			</div>
		</main>
	{:else if user}
		<main class="flex-1 container pb-8 pt-36 space-y-12">
			<div class="flex items-center justify-between pt-4">
				<div class="space-y-1">
					<h2 class="text-3xl font-bold tracking-tight">{t('common.overview')}</h2>
					<p class="text-sm text-muted-foreground">{t('dashboard.subtitle')}</p>
				</div>
				<div class="flex items-center space-x-2">
					<Badge variant="outline" class="font-mono text-[10px] text-muted-foreground bg-muted/30">
						v1.0.4-stable
					</Badge>
				</div>
			</div>

			<Tabs.Root bind:value={activeTab} class="space-y-4">
				<Tabs.List>
					<Tabs.Trigger value="overview" class="data-[state=active]:text-primary font-semibold">
						{t('common.overview')}
					</Tabs.Trigger>
					<Tabs.Trigger value="api-access" class="data-[state=active]:text-primary font-semibold">
						{t('dashboard.api_access')}
					</Tabs.Trigger>
					<Tabs.Trigger
						value="settings"
						disabled
						class="data-[state=active]:text-primary font-semibold"
					>
						{t('common.settings')}
					</Tabs.Trigger>
				</Tabs.List>

				<Tabs.Content value="overview" class="space-y-4">
					<div in:fade={{ duration: 200 }} class="space-y-4">
						<!-- Top Stats -->
						<div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
							<Card>
								<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
									<CardTitle
										class="text-sm font-medium uppercase tracking-wider text-muted-foreground"
										>{t('dashboard.system_status')}</CardTitle
									>
									<div class="p-2 bg-green-500/10 rounded-full">
										<Activity class="h-4 w-4 text-green-500" />
									</div>
								</CardHeader>
								<CardContent>
									<div class="text-2xl font-bold text-green-500">{t('dashboard.active')}</div>
									<p class="text-[10px] text-muted-foreground mt-1">
										{t('dashboard.stats.status_desc')}
									</p>
								</CardContent>
							</Card>
							<Card>
								<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
									<CardTitle
										class="text-sm font-medium uppercase tracking-wider text-muted-foreground"
										>{t('dashboard.stats.security')}</CardTitle
									>
									<div class="p-2 bg-blue-500/10 rounded-full">
										<ShieldCheck class="h-4 w-4 text-blue-500" />
									</div>
								</CardHeader>
								<CardContent>
									<div class="text-2xl font-bold">{t('dashboard.stats.standard')}</div>
									<p class="text-[10px] text-muted-foreground mt-1">
										{t('dashboard.stats.security_desc')}
									</p>
								</CardContent>
							</Card>
							<Card>
								<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
									<CardTitle
										class="text-sm font-medium uppercase tracking-wider text-muted-foreground"
										>{t('dashboard.stats.access_tier')}</CardTitle
									>
									<div class="p-2 bg-orange-500/10 rounded-full">
										<Zap class="h-4 w-4 text-orange-500" />
									</div>
								</CardHeader>
								<CardContent>
									<div class="flex items-center gap-2">
										<div class="text-2xl font-bold">
											{t('dashboard.stats.keys_count', { count: 1 })}
										</div>
										<Badge variant="secondary" class="text-[10px] h-4">{t('common.free')}</Badge>
									</div>
									<p class="text-[10px] text-muted-foreground mt-1">
										{t('dashboard.stats.access_tier_desc')}
									</p>
								</CardContent>
							</Card>
							<Card>
								<CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
									<CardTitle
										class="text-sm font-medium uppercase tracking-wider text-muted-foreground"
										>{t('dashboard.stats.last_login')}</CardTitle
									>
									<div class="p-2 bg-purple-500/10 rounded-full">
										<LayoutDashboard class="h-4 w-4 text-purple-500" />
									</div>
								</CardHeader>
								<CardContent>
									<div class="text-2xl font-bold">
										{t('common.today')}, {new Date().toLocaleTimeString([], {
											hour: '2-digit',
											minute: '2-digit'
										})}
									</div>
									<p class="text-[10px] text-muted-foreground mt-1">
										{t('dashboard.stats.last_login_desc')}
									</p>
								</CardContent>
							</Card>
						</div>

						<div class="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
							<!-- Profile Card -->
							<Card class="lg:col-span-3">
								<CardHeader>
									<CardTitle>{t('dashboard.profile_title')}</CardTitle>
									<CardDescription>{t('dashboard.profile_desc')}</CardDescription>
								</CardHeader>
								<CardContent class="flex flex-col items-center pt-2 pb-6">
									<Avatar.Root class="h-24 w-24 border-2 border-primary/10 shadow-sm mb-4">
										<Avatar.Fallback
											class="text-2xl font-bold bg-gradient-to-br from-primary/80 to-primary text-primary-foreground"
										>
											{getInitials(user.name)}
										</Avatar.Fallback>
									</Avatar.Root>
									<h3 class="text-2xl font-bold">{user.name}</h3>
									<div class="flex items-center gap-2 mt-1">
										<span class="text-sm font-mono text-muted-foreground">@{user.username}</span>
										<Badge variant="outline" class="text-[10px] h-4">{t('common.verified')}</Badge>
									</div>
									<Separator class="my-6 w-full" />
									<div class="w-full space-y-3">
										<div class="flex justify-between text-sm">
											<span class="text-muted-foreground">{t('common.email')}</span>
											<span class="font-medium">{user.email}</span>
										</div>
										<div class="flex justify-between text-sm">
											<span class="text-muted-foreground">{t('dashboard.id_number')}</span>
											<span class="font-mono text-xs">{user.userId}</span>
										</div>
									</div>
								</CardContent>
							</Card>

							<!-- Shortcut / Action Card -->
							<Card class="lg:col-span-4 overflow-hidden">
								<CardHeader>
									<CardTitle>{t('dashboard.management_title')}</CardTitle>
									<CardDescription>{t('dashboard.management_desc')}</CardDescription>
								</CardHeader>
								<CardContent class="space-y-4">
									{#if currentApiKey}
										<div class="space-y-4" in:slide>
											<div class="flex items-center justify-between mb-2">
												<div class="flex items-center gap-2">
													<ShieldCheck class="w-4 h-4 text-green-500" />
													<span class="text-sm font-medium">{t('dashboard.active_key')}</span>
												</div>
												<Badge
													variant="outline"
													class="bg-green-500/5 text-green-600 border-green-500/20"
													>{t('dashboard.operational')}</Badge
												>
											</div>
											<div
												class="relative flex items-center justify-between p-5 bg-muted/40 border-2 border-border/60 rounded-xl overflow-hidden group transition-all hover:border-primary/20"
												onmouseenter={() => (hoveredKey = true)}
												onmouseleave={() => (hoveredKey = false)}
												role="group"
											>
												<div
													class="font-mono text-xl text-primary tracking-wider truncate transition-all duration-500 {hoveredKey
														? 'blur-none opacity-100'
														: 'blur-md opacity-40 select-none'}"
												>
													{currentApiKey}
												</div>
												<div class="flex items-center gap-2 ml-4">
													<Button
														variant="outline"
														size="icon"
														class="rounded-full h-10 w-10"
														onclick={() => copyToClipboard(currentApiKey, 'API Key')}
														title={t('dashboard.copy')}
													>
														<Copy class="w-4 h-4" />
													</Button>
													<Button
														variant="destructive"
														size="icon"
														class="rounded-full h-10 w-10 bg-destructive/10 text-destructive hover:bg-destructive hover:text-destructive-foreground border-none"
														onclick={() => (isRevokeDialogOpen = true)}
														disabled={keyLoading}
														title={t('dashboard.revoke')}
													>
														<Trash2 class="w-4 h-4" />
													</Button>
												</div>
											</div>
											<div
												class="flex items-center justify-center gap-2 text-[10px] text-muted-foreground uppercase tracking-tighter"
											>
												<div class="h-px w-8 bg-border"></div>
												{t('dashboard.hover_to_view')}
												<div class="h-px w-8 bg-border"></div>
											</div>
										</div>
									{:else}
										<EmptyState
											title={t('dashboard.no_key')}
											description={t('dashboard.no_key_desc')}
											icon={ShieldAlert}
											class="min-h-[250px] border-border/50 bg-muted/20"
										>
											<Button
												onclick={generateApiKey}
												disabled={keyLoading}
												class="w-full max-w-xs px-8"
											>
												{#if keyLoading}
													<Loader2 class="w-4 h-4 mr-2 animate-spin" />
													{t('dashboard.generating')}
												{:else}
													<Key class="w-4 h-4 mr-2" />
													{t('dashboard.generate_key')}
												{/if}
											</Button>
										</EmptyState>
									{/if}

									<Separator class="my-4" />

									<Alert.Root class="bg-muted/30 border-border/50">
										<ExternalLink class="h-4 w-4" />
										<Alert.Title class="text-sm font-semibold"
											>{t('dashboard.docs_title')}</Alert.Title
										>
										<Alert.Description class="text-xs text-muted-foreground">
											{t('dashboard.docs_desc')}
										</Alert.Description>
									</Alert.Root>
								</CardContent>
							</Card>
						</div>
					</div></Tabs.Content
				>

				<Tabs.Content value="api-access">
					<div in:fade={{ duration: 200 }} class="space-y-4">
						<Card>
							<CardHeader>
								<CardTitle>{t('dashboard.logs_title')}</CardTitle>
								<CardDescription>
									{t('dashboard.logs_desc')}
								</CardDescription>
							</CardHeader>
							<CardContent
								class="h-[400px] flex items-center justify-center border-t border-dashed mt-4"
							>
								<p class="text-sm text-muted-foreground">{t('dashboard.logs_coming_soon')}</p>
							</CardContent>
						</Card>
					</div>
				</Tabs.Content>
			</Tabs.Root>
		</main>

		<!-- Revoke Dialog -->
		<Dialog.Root bind:open={isRevokeDialogOpen}>
			<Dialog.Content class="sm:max-w-[425px]">
				<Dialog.Header>
					<Dialog.Title class="text-2xl">{t('dashboard.revoke_title')}</Dialog.Title>
					<Dialog.Description class="pt-2">
						{t('dashboard.revoke_confirm')}
					</Dialog.Description>
				</Dialog.Header>
				<div class="bg-destructive/10 p-4 rounded-lg flex gap-3 my-4">
					<ShieldAlert class="w-5 h-5 text-destructive shrink-0" />
					<p class="text-xs text-destructive font-medium leading-tight">
						{t('dashboard.revoke_warning')}
					</p>
				</div>
				<Dialog.Footer>
					<Button variant="ghost" onclick={() => (isRevokeDialogOpen = false)}
						>{t('common.cancel')}</Button
					>
					<Button variant="destructive" onclick={revokeApiKey} disabled={keyLoading}
						>{t('dashboard.revoke')}</Button
					>
				</Dialog.Footer>
			</Dialog.Content>
		</Dialog.Root>
	{/if}
</div>

<style>
	:global(.container) {
		max-width: 1200px;
		margin: 0 auto;
		padding: 0 1rem;
	}
</style>
