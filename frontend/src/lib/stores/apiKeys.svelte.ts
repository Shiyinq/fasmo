import { apiKeys as apiKeysApi } from '$lib/apis/api_keys';

let currentKey = $state('');
let isLoading = $state(false);
let error = $state('');

export function createApiKeysStore() {
	return {
		get currentKey() {
			return currentKey;
		},
		get isLoading() {
			return isLoading;
		},
		get error() {
			return error;
		},

		create: async () => {
			isLoading = true;
			error = '';
			try {
				const res = await apiKeysApi.create();
				currentKey = res.apiKey;
				return res;
			} catch (e: any) {
				error = e.detail || 'Failed to generate key.';
				throw e;
			} finally {
				isLoading = false;
			}
		},

		revoke: async () => {
			const previousKey = currentKey; // Backup for rollback
			currentKey = ''; // Optimistic update
			isLoading = true;

			try {
				await apiKeysApi.revoke();
			} catch (e: any) {
				currentKey = previousKey; // Rollback if API fails
				error = e.detail || 'Failed to revoke key.';
				throw e;
			} finally {
				isLoading = false;
			}
		},

		clear: () => {
			currentKey = '';
			error = '';
		}
	};
}

export const apiKeysStore = createApiKeysStore();
