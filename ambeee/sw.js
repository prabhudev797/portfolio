let cryptoKey = null;

self.addEventListener('install', event => {
    self.skipWaiting();
});

self.addEventListener('activate', event => {
    event.waitUntil(clients.claim());
});

self.addEventListener('message', async event => {
    if (event.data && event.data.type === 'SET_KEY') {
        const hashHex = event.data.key;
        const hashArray = new Uint8Array(hashHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        cryptoKey = await crypto.subtle.importKey(
            'raw',
            hashArray,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        event.source.postMessage('KEY_SET');
    }
});

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    // Intercept image requests to any /photos/ path (handles Vite base path issues)
    if (url.pathname.includes('/photos/') && url.pathname.match(/\.(jpg|jpeg|png)$/)) {
        event.respondWith(handleImageRequest(url));
    }
});

async function handleImageRequest(url) {
    if (!cryptoKey) {
        // If not authenticated, return a 401 or a blank image
        return new Response('Unauthorized', { status: 401 });
    }

    try {
        const filename = url.pathname.substring(url.pathname.lastIndexOf('/') + 1);
        const encUrl = new URL('./photos/' + filename + '.enc', self.registration.scope).href;

        const response = await fetch(encUrl);
        if (!response.ok) return response;

        const buffer = await response.arrayBuffer();
        const data = new Uint8Array(buffer);

        // Extract IV and Encrypted Data
        const iv = data.slice(0, 12);
        const encrypted = data.slice(12);

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            encrypted
        );

        return new Response(decryptedBuffer, {
            headers: { 'Content-Type': 'image/jpeg' }
        });
    } catch (e) {
        console.error('Decryption failed for', url.href, e);
        return new Response('Decryption Failed', { status: 403 });
    }
}
