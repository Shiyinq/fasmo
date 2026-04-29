import { auth as authApi } from '$lib/apis/auth';
import type {
	LoginRequest,
	RegisterRequest,
	PasswordResetRequest,
	PasswordResetConfirmRequest,
	VerifyEmailRequest
} from '$lib/types';
import { accessToken } from '$lib/stores/accessToken.svelte';
import { isAuthenticated } from '$lib/stores/authStatus.svelte';
import { createRequestDedup } from '$lib/utils/requestDedup';

/**
 * Auth actions service - migrated to Svelte 5 Shared Rune State.
 * Provides methods for login, logout, registration and password management.
 */

let isLoading = $state(false);
let error = $state('');
let isLoggingOut = $state(false);
const dedup = createRequestDedup();

export function createAuthStore() {
	return {
		get isLoading() {
			return isLoading;
		},
		get error() {
			return error;
		},
		get isLoggingOut() {
			return isLoggingOut;
		},

		login: async (credentials: LoginRequest) => {
			isLoading = true;
			error = '';
			try {
				const response = await authApi.login(credentials);
				if (response.access_token) {
					accessToken.set(response.access_token);
					isAuthenticated.set(true);
				}
				return response;
			} catch (e: any) {
				error = e.detail || 'Login failed.';
				throw e;
			} finally {
				isLoading = false;
			}
		},

		register: async (data: RegisterRequest) => {
			isLoading = true;
			error = '';
			try {
				const res = await authApi.register(data);
				return res;
			} catch (e: any) {
				error = e.detail || 'Registration failed.';
				throw e;
			} finally {
				isLoading = false;
			}
		},

		logout: async () => {
			if (isLoggingOut) return;
			isLoggingOut = true;
			isLoading = true;
			try {
				const response = await authApi.logout();
				return response;
			} finally {
				accessToken.set('');
				isAuthenticated.set(false);
				isLoggingOut = false;
				isLoading = false;
			}
		},

		getProfile: async () => {
			return dedup.execute('profile', () => authApi.getProfile());
		},

		forgotPassword: async (data: PasswordResetRequest) => {
			isLoading = true;
			error = '';
			try {
				return await authApi.forgotPassword(data);
			} catch (e: any) {
				error = e.detail || 'Recovery request failed.';
				throw e;
			} finally {
				isLoading = false;
			}
		},

		resetPassword: async (data: PasswordResetConfirmRequest) => {
			isLoading = true;
			error = '';
			try {
				return await authApi.resetPassword(data);
			} catch (e: any) {
				error = e.detail || 'Password reset failed.';
				throw e;
			} finally {
				isLoading = false;
			}
		},

		verifyEmail: async (data: VerifyEmailRequest) => {
			isLoading = true;
			error = '';
			try {
				return await authApi.verifyEmail(data);
			} catch (e: any) {
				error = e.detail || 'Email verification failed.';
				throw e;
			} finally {
				isLoading = false;
			}
		},

		get googleLoginUrl() {
			return authApi.googleLoginUrl;
		},
		get githubLoginUrl() {
			return authApi.githubLoginUrl;
		},

		clearError: () => {
			error = '';
		}
	};
}

export const authStore = createAuthStore();
