export interface ApiError {
	detail: string | Array<{ msg: string; loc: Array<string | number> }>;
}

export interface GenericResponse {
	message: string;
}

export interface Toast {
	id: string;
	message: string;
	type: 'success' | 'error' | 'info' | 'warning';
	duration?: number;
}
