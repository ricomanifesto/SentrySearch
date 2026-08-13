const AUTH_REDIRECT_ORIGIN = 'https://sentrysearch.local';

export function getSafeNextPath(value: string | null | undefined): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) {
    return '/dashboard';
  }

  try {
    const url = new URL(value, AUTH_REDIRECT_ORIGIN);
    const origin = new URL(AUTH_REDIRECT_ORIGIN).origin;
    if (url.origin !== origin) {
      return '/dashboard';
    }
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return '/dashboard';
  }
}
