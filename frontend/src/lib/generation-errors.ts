import axios from 'axios';

export function getGenerationErrorMessage(error: unknown): string {
  if (!axios.isAxiosError(error)) {
    return 'The report could not be started. Try again, or return to saved reports while the service recovers.';
  }

  if (error.response?.status === 422) {
    return 'Check the target name, remove unsupported characters, and try again.';
  }

  if (error.code === 'ECONNABORTED') {
    return 'The research service did not respond in time. The first run can take longer while the service wakes; try again in a moment.';
  }

  if (error.response && error.response.status >= 500) {
    return 'The research service is unavailable or still waking. Your target was not the cause; try again shortly.';
  }

  if (error.request && !error.response) {
    return 'SentrySearch could not reach the research service. Check your connection and try again.';
  }

  return 'The report could not be started. Try again, or return to saved reports while the service recovers.';
}
