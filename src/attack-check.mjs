export async function runAttackChecks(config) {
 if (config.step < 3) {
    throw new Error('3단계 공격 점검 설정을 확인해 주세요.');
  }

  let app;

  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('배포 주소가 올바르지 않습니다.');
  }

  if (
    app.protocol !== 'https:' ||
    app.username ||
    app.password ||
    app.search ||
    app.hash ||
    app.pathname !== '/' ||
    !app.hostname.endsWith('.vercel.app')
  ) {
    throw new Error('HTTPS Vercel 배포 주소를 확인해 주세요.');
  }

  const response = await fetch(
    new URL('/api/note', app),
    {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: {
        Accept: 'application/json'
      }
    }
  );

  let jsonError = false;

  try {
    const data = await response.json();

    jsonError =
      data !== null &&
      typeof data === 'object' &&
      !Array.isArray(data) &&
      typeof data.error === 'string' &&
      data.error.length > 0;
  } catch {
    jsonError = false;
  }

  const blocked =
    [401, 403].includes(response.status) &&
    jsonError;

  if (!blocked) {
    throw new Error(
      `비로그인 접근 차단 실패: HTTP ${response.status}, JSON 오류 응답: ${jsonError}`
    );
  }

  return [
    {
      attackId: 'anonymous_note_read',
      expected: '비로그인 메모 조회 요청에 HTTP 401 또는 403과 JSON 오류 응답',
      observed: 'not_run'
    }
  ];
}
