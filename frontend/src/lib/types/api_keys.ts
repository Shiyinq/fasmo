export interface APIKey {
	id: number;
	key: string;
	user_id: number;
	created_at: string;
	is_active: boolean;
}

export interface APIKeyResponse {
	apiKey: string;
}
