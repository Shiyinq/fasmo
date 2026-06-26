import type { LoginData, RegisterData, UserProfile } from '$lib/schemas';

export type LoginRequest = LoginData;
export type RegisterRequest = RegisterData;
export type User = UserProfile;

export interface AuthResponse {
	access_token: string;
	token_type: string;
}

export interface PasswordResetRequest {
	email: string;
}

export interface PasswordResetConfirmRequest {
	token: string;
	new_password: string;
	confirm_password?: string;
}

export interface EmailVerificationRequest {
	email: string;
}

export interface VerifyEmailRequest {
	token: string;
}
