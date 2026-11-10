// Vercel Routing Middleware: every request must carry a valid sign-in cookie, or it gets the login screen.
// The password is the WORKBENCH_PASSWORD environment variable set in Vercel. It is never stored in this repository.

export const config = { matcher: '/:path*' };

const COOKIE = 'workbench_session';

async function tokenFor(password) {
  const bytes = new TextEncoder().encode(`workbench:${password}`);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function cookieValue(request) {
  const header = request.headers.get('cookie') || '';
  const found = header.split(';').map((c) => c.trim()).find((c) => c.startsWith(`${COOKIE}=`));
  return found ? found.slice(COOKIE.length + 1) : '';
}

function loginPage(message, status) {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Workbench · Sign in</title>
<style>
  :root { --red: #E31837; --ink: #1F1F1F; --muted: #6B665E; --cream: #F6F2EA; --line: #E5DFD3; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px; background: var(--cream); color: var(--ink); font-family: system-ui, -apple-system, "Segoe UI", Arial, sans-serif; }
  .card { width: 100%; max-width: 380px; background: #fff; border: 1px solid var(--line); border-radius: 14px; padding: 32px 28px; box-shadow: 0 8px 30px rgba(31, 31, 31, 0.06); }
  .brand { font-size: 12px; color: var(--muted); letter-spacing: 0.02em; }
  h1 { margin: 6px 0 4px; font-size: 26px; }
  p { margin: 0 0 22px; color: var(--muted); font-size: 14px; line-height: 1.45; }
  label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; }
  input { width: 100%; padding: 11px 12px; font-size: 15px; border: 1px solid var(--line); border-radius: 8px; }
  input:focus { outline: 2px solid var(--red); outline-offset: 1px; border-color: transparent; }
  button { width: 100%; margin-top: 16px; padding: 12px; font-size: 15px; font-weight: 600; color: #fff; background: var(--red); border: 0; border-radius: 8px; cursor: pointer; }
  button:hover { filter: brightness(0.94); }
  .error { margin: 0 0 16px; padding: 10px 12px; font-size: 13px; color: #8A0F22; background: #FDECEE; border-radius: 8px; }
  .bar { height: 4px; background: var(--red); border-radius: 14px 14px 0 0; margin: -32px -28px 26px; }
</style>
</head>
<body>
  <form class="card" method="post" action="/__login">
    <div class="bar"></div>
    <div class="brand">Tech Mahindra for Vodafone UK</div>
    <h1>Workbench</h1>
    <p>This demo is private. Enter the password you were given to continue.</p>
    ${message ? `<div class="error" role="alert">${message}</div>` : ''}
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>`;
  return new Response(html, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

export default async function middleware(request) {
  const password = process.env.WORKBENCH_PASSWORD;
  // With no password set in Vercel, nobody gets in.
  if (!password) return loginPage('Sign-in is not set up yet. Please contact the demo owner.', 503);

  const url = new URL(request.url);
  const expected = await tokenFor(password);

  if (url.pathname === '/__login' && request.method === 'POST') {
    const form = await request.formData();
    if (form.get('password') !== password) return loginPage('That password is not right. Please try again.', 401);
    // A session cookie: it lasts until the browser is closed, so each new visit asks again.
    return new Response(null, {
      status: 303,
      headers: { location: '/', 'set-cookie': `${COOKIE}=${expected}; Path=/; HttpOnly; Secure; SameSite=Lax`, 'cache-control': 'no-store' },
    });
  }

  if (cookieValue(request) === expected) return new Response(null, { headers: { 'x-middleware-next': '1' } });
  return loginPage('', 401);
}
