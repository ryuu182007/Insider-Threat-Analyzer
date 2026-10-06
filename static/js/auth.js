/**
 * ThreatSim - per-tab authentication helper.
 *
 * The session token lives in sessionStorage, which is private to ONE browser tab.
 *  - Refreshing the page keeps the token  -> no logout on refresh.
 *  - Another tab / another browser has its own token -> separate users never overlap.
 */
(function () {
    const KEY = 'threatsim.token';
    const PORTAL_KEY = 'threatsim.portal';
    let currentUser = null;

    const Auth = {
        token() { try { return sessionStorage.getItem(KEY); } catch (e) { return null; } },
        portal() { try { return sessionStorage.getItem(PORTAL_KEY); } catch (e) { return null; } },
        save(token, portal) {
            sessionStorage.setItem(KEY, token);
            sessionStorage.setItem(PORTAL_KEY, portal);
        },
        clear() {
            try {
                sessionStorage.removeItem(KEY);
                sessionStorage.removeItem(PORTAL_KEY);
                sessionStorage.removeItem('threatsim.page');
            } catch (e) { /* ignore */ }
            currentUser = null;
        },
        user() { return currentUser; },

        /** fetch() that always carries THIS tab's token and handles expiry. */
        async fetch(url, options = {}) {
            const opts = Object.assign({}, options);
            opts.headers = Object.assign({}, options.headers || {});
            const t = Auth.token();
            if (t) opts.headers['Authorization'] = 'Bearer ' + t;
            opts.cache = 'no-store';
            const res = await fetch(url, opts);
            if (res.status === 401 && !url.includes('/auth/login')) {
                Auth.clear();
                window.location.replace('/login?expired=1');
                throw new Error('Session expired. Please sign in again.');
            }
            return res;
        },

        /** Verify this tab is signed in with the right portal. Returns the user or redirects. */
        async require(portal) {
            if (!Auth.token()) { window.location.replace('/login'); return new Promise(() => {}); }
            let res;
            try { res = await fetch('/api/auth/me', { headers: { Authorization: 'Bearer ' + Auth.token() }, cache: 'no-store' }); }
            catch (e) { document.body.style.visibility = 'visible'; throw e; }   // server unreachable: don't log out
            if (res.status === 401) { Auth.clear(); window.location.replace('/login?expired=1'); return new Promise(() => {}); }
            const user = await res.json();
            if (user.role_type !== portal) {
                window.location.replace(user.role_type === 'admin' ? '/' : '/member');
                return new Promise(() => {});
            }
            currentUser = user;
            Auth.bind(user);
            document.body.style.visibility = 'visible';
            return user;
        },

        /** Fill [data-bind="name|id|username|department|role"] elements. */
        bind(user) {
            document.querySelectorAll('[data-bind]').forEach(el => {
                const k = el.getAttribute('data-bind');
                if (k === 'initials') {
                    el.textContent = (user.name || user.username || '?').trim().slice(0, 2).toUpperCase();
                } else if (user[k] !== undefined && user[k] !== null) {
                    el.textContent = user[k];
                }
            });
        },

        async logout() {
            const t = Auth.token();
            Auth.clear();
            try {
                if (t) await fetch('/api/auth/logout', { method: 'POST', headers: { Authorization: 'Bearer ' + t } });
            } catch (e) { /* ignore */ }
            window.location.replace('/login');
        }
    };

    window.Auth = Auth;
})();
