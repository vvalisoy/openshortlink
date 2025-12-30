import { Context, Next } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { HTTPException } from 'hono/http-exception';

const CSRF_COOKIE_NAME = 'csrf_token';
const CSRF_HEADER_NAME = 'X-CSRF-Token';
const CSRF_FORM_FIELD = '_csrf';

export const csrfProtection = async (c: Context, next: Next) => {
    // 1. Get existing token from cookie
    let token = getCookie(c, CSRF_COOKIE_NAME);

    // 2. If no token exists, generate a new one
    if (!token) {
        token = crypto.randomUUID();
        setCookie(c, CSRF_COOKIE_NAME, token, {
            path: '/',
            secure: true, // Always secure in production (Cloudflare Workers implies HTTPS)
            httpOnly: true, // Prevent JS access to the cookie itself
            sameSite: 'Strict',
        });
    }

    // 3. Make token available to views/handlers
    c.set('csrfToken', token);

    // 4. Check if request method is safe
    const safeMethods = ['GET', 'HEAD', 'OPTIONS', 'TRACE'];
    if (safeMethods.includes(c.req.method)) {
        return next();
    }

    // 5. For unsafe methods, verify the token
    const headerToken = c.req.header(CSRF_HEADER_NAME);

    // For multipart/form-data or application/x-www-form-urlencoded, we might need to parse body
    // But parsing body here might consume it, causing issues for downstream handlers.
    // Ideally, clients should send the header. 
    // For simple HTML forms, we can try to read from form data if header is missing,
    // but Hono's c.req.parseBody() is async and consumes the stream.
    // Strategy: Prioritize Header. If missing and it's a form submission, we might need to rely on the handler to check, 
    // OR we assume standard fetch calls will use headers.
    // For standard HTML forms (POST), we can't easily check body without consuming it.
    // However, we can clone the request? No, that's expensive.

    // Let's stick to Header validation for API/Fetch calls.
    // For HTML Forms, we will need to ensure the form sends the token.
    // If we want to support HTML forms, we have to parse the body.
    // Let's try to get it from header first.

    let submittedToken = headerToken;

    if (!submittedToken) {
        // If content type is form data, try to parse
        const contentType = c.req.header('Content-Type') || '';
        if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
            try {
                // Clone request to not consume the original body for downstream
                const clonedReq = c.req.raw.clone();
                const formData = await clonedReq.formData();
                submittedToken = formData.get(CSRF_FORM_FIELD) as string;
            } catch (e) {
                // Ignore parsing errors
            }
        }
    }

    if (!submittedToken || submittedToken !== token) {
        throw new HTTPException(403, { message: 'Invalid CSRF token' });
    }

    return next();
};
