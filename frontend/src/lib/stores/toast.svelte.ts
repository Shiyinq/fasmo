import type { Toast } from '$lib/types';

let toasts = $state<Toast[]>([]);

export const toastStore = {
	get items() {
		return toasts;
	},
	add: (message: string, type: Toast['type'] = 'info', duration = 3000) => {
		const id = crypto.randomUUID();
		toasts.push({ id, message, type, duration });

		if (duration > 0) {
			setTimeout(() => {
				toastStore.remove(id);
			}, duration);
		}
	},
	remove: (id: string) => {
		toasts = toasts.filter((t) => t.id !== id);
	},
	success: (msg: string) => toastStore.add(msg, 'success'),
	error: (msg: string) => toastStore.add(msg, 'error'),
	info: (msg: string) => toastStore.add(msg, 'info'),
	warning: (msg: string) => toastStore.add(msg, 'warning')
};

export const addToast = toastStore.add;
