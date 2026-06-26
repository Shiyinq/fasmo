import { client } from './client';
import type { APIKeyResponse } from '$lib/types';

export const apiKeys = {
	create: async (): Promise<APIKeyResponse> => {
		return client<APIKeyResponse>('/key', {
			method: 'POST'
		});
	},

	revoke: async (): Promise<APIKeyResponse> => {
		return client<APIKeyResponse>('/key', { method: 'DELETE' });
	}
};
