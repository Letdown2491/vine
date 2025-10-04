import { toDataURL } from 'qrcode';
import { createNip46Codec, Nip46Codec } from './lib/nip46/codec';
import { createDefaultCodecConfig } from './lib/nip46/encryption';
import { LocalStorageAdapter, MemoryStorageAdapter } from './lib/nip46/storage';
import { SessionManager, RemoteSignerSession, SessionSnapshot } from './lib/nip46/session';
import { Nip46Service } from './lib/nip46/service';
import { createSimplePoolTransport } from './lib/nip46/transport/simplePoolTransport';

const DEFAULT_RELAYS = ['wss://relay.primal.net'];

type UiElements = {
  status: HTMLElement;
  openButton: HTMLButtonElement;
  inviteContainer: HTMLElement;
  qrImage: HTMLImageElement;
  uriContainer: HTMLElement;
  uriValue: HTMLElement;
  copyButton: HTMLButtonElement;
  error: HTMLElement;
  welcome: HTMLElement;
};

const createSessionManager = (): SessionManager => {
  if (typeof window === 'undefined') {
    return new SessionManager(new MemoryStorageAdapter());
  }
  return new SessionManager(new LocalStorageAdapter());
};

const pickActiveSession = (snapshot: SessionSnapshot) =>
  snapshot.sessions.find(session => session.status === 'active' && !session.lastError) ?? null;

const selectInvitationSession = (snapshot: SessionSnapshot) => {
  const candidates = snapshot.sessions
    .filter(session => session.status !== 'revoked' && !session.userPubkey)
    .sort((a, b) => b.createdAt - a.createdAt);
  return candidates[0] ?? null;
};

const formatUri = (uri: string) => uri.replace(/(.{64})/g, '$1\n');

const updateUri = (ui: UiElements, uri: string | null) => {
  if (!uri) {
    ui.uriContainer.hidden = true;
    ui.uriValue.textContent = '';
    ui.copyButton.disabled = true;
    ui.copyButton.textContent = 'Copy link';
    return;
  }
  ui.uriContainer.hidden = false;
  ui.uriValue.textContent = formatUri(uri);
  ui.copyButton.disabled = false;
  ui.copyButton.textContent = 'Copy link';
};

const updateError = (ui: UiElements, message: string | null) => {
  if (!message) {
    ui.error.hidden = true;
    ui.error.textContent = '';
    return;
  }
  ui.error.hidden = false;
  ui.error.textContent = message;
};

const sessionNeedsPubkey = (session: RemoteSignerSession) =>
  session.status === 'active' && session.remoteSignerPubkey && !session.userPubkey &&
  session.permissions.includes('get_public_key');

const buildUriFromSession = (session: RemoteSignerSession) => {
  const params = new URLSearchParams();
  session.relays.forEach(relay => params.append('relay', relay));
  if (session.nostrConnectSecret) params.set('secret', session.nostrConnectSecret);
  if (session.permissions.length) params.set('perms', session.permissions.join(','));
  if (session.metadata) params.set('metadata', JSON.stringify(session.metadata));
  const query = params.toString();
  return query
    ? `nostrconnect://${encodeURIComponent(session.clientPublicKey)}?${query}`
    : `nostrconnect://${encodeURIComponent(session.clientPublicKey)}`;
};

export const initRemoteSigner = async () => {
  if (typeof document === 'undefined') return;
  const root = document.getElementById('remote-signer-root');
  if (!root) return;

  const status = root.querySelector('[data-status]') as HTMLElement | null;
  const openButton = root.querySelector('[data-open-invite]') as HTMLButtonElement | null;
  const inviteContainer = root.querySelector('[data-invite]') as HTMLElement | null;
  const qrImage = root.querySelector('[data-qr]') as HTMLImageElement | null;
  const uriContainer = root.querySelector('[data-uri-container]') as HTMLElement | null;
  const uriValue = root.querySelector('[data-uri-value]') as HTMLElement | null;
  const copyButton = root.querySelector('[data-copy-uri]') as HTMLButtonElement | null;
  const error = root.querySelector('[data-error]') as HTMLElement | null;
  const welcome = root.querySelector('[data-welcome]') as HTMLElement | null;

  if (
    !status ||
    !openButton ||
    !inviteContainer ||
    !qrImage ||
    !uriContainer ||
    !uriValue ||
    !copyButton ||
    !error ||
    !welcome
  ) {
    return;
  }

  const ui: UiElements = {
    status,
    openButton,
    inviteContainer,
    qrImage,
    uriContainer,
    uriValue,
    copyButton,
    error,
    welcome,
  };

  ui.inviteContainer.hidden = true;
  ui.qrImage.hidden = true;
  ui.welcome.hidden = true;
  ui.openButton.hidden = false;
  ui.openButton.disabled = false;
  ui.openButton.textContent = 'Connect with Remote Signer';
  ui.status.hidden = false;
  updateUri(ui, null);
  updateError(ui, null);

  const sessionManager = createSessionManager();
  const codec: Nip46Codec = createNip46Codec(createDefaultCodecConfig());
  const relaySet = new Set(DEFAULT_RELAYS);
  const service = new Nip46Service({
    codec,
    sessionManager,
    transport: createSimplePoolTransport(() => Array.from(relaySet)),
  });

  const fetchTracker = new Map<string, number>();

  let currentUri: string | null = null;
  let lastQrForUri: string | null = null;
  let invitationRequested = false;
  let invitationSessionId: string | null = null;
  let isGenerating = false;

  const hideInvitation = () => {
    ui.inviteContainer.hidden = true;
    ui.qrImage.hidden = true;
    ui.qrImage.removeAttribute('src');
    updateUri(ui, null);
    currentUri = null;
    lastQrForUri = null;
  };

  const showInvitation = () => {
    ui.inviteContainer.hidden = false;
    ui.status.hidden = false;
  };

  const showWelcome = () => {
    ui.status.hidden = false;
    ui.status.textContent = 'Remote signer connected.';
    ui.openButton.hidden = true;
    ui.welcome.hidden = false;
    ui.error.hidden = true;
    hideInvitation();
  };

  const renderQrCode = async (uri: string) => {
    if (lastQrForUri === uri) {
      ui.qrImage.hidden = false;
      return;
    }
    try {
      const dataUrl = await toDataURL(uri, { width: 220, margin: 1 });
      ui.qrImage.src = dataUrl;
      ui.qrImage.hidden = false;
      lastQrForUri = uri;
    } catch (error) {
      ui.qrImage.hidden = true;
      lastQrForUri = null;
      updateError(ui, 'Failed to render QR code.');
    }
  };

  const refreshInvitation = async (snapshot: SessionSnapshot, options: { forceNew?: boolean } = {}) => {
    if (!invitationRequested) return;
    if (isGenerating) return;
    isGenerating = true;
    ui.openButton.disabled = true;
    ui.status.textContent = 'Generating remote signer invitation…';
    updateError(ui, null);

    if (options.forceNew && invitationSessionId) {
      await sessionManager.removeSession(invitationSessionId).catch(() => undefined);
      invitationSessionId = null;
      currentUri = null;
      lastQrForUri = null;
    }

    let session: RemoteSignerSession | null = null;

    if (!options.forceNew && invitationSessionId) {
      session = snapshot.sessions.find(item => item.id === invitationSessionId) ?? null;
    }
    if (!session && !options.forceNew) {
      session = selectInvitationSession(snapshot);
    }

    if (!session) {
      try {
        const result = await service.createInvitation({
          relays: Array.from(relaySet),
          metadata: { name: 'Vine Watcher', url: 'https://github.com/Letdown2491/bloom' },
        });
        session = result.session;
        invitationSessionId = session.id;
        currentUri = result.uri;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        ui.status.textContent = 'Unable to create remote signer invitation.';
        updateError(ui, message);
        ui.openButton.disabled = false;
        isGenerating = false;
        return;
      }
    }

    if (!session) {
      ui.openButton.disabled = false;
      isGenerating = false;
      return;
    }

    invitationSessionId = session.id;
    const derivedUri = buildUriFromSession(session);
    currentUri = derivedUri;

    if (!invitationRequested) {
      ui.openButton.textContent = 'Connect with Remote Signer';
      ui.openButton.disabled = false;
      isGenerating = false;
      return;
    }

    showInvitation();
    ui.openButton.textContent = 'Generate New Link';
    updateUri(ui, currentUri);
    await renderQrCode(currentUri);
    ui.status.textContent = 'Scan or paste this Nostr Connect link with your remote signer.';
    ui.status.hidden = false;
    ui.openButton.disabled = false;
    isGenerating = false;
  };

  const handleSnapshot = (snapshot: SessionSnapshot) => {
    const nextRelays = new Set(DEFAULT_RELAYS);
    snapshot.sessions.forEach(session => {
      session.relays.forEach(relay => {
        const trimmed = relay.trim();
        if (trimmed) nextRelays.add(trimmed);
      });
    });
    relaySet.clear();
    nextRelays.forEach(relay => relaySet.add(relay));

    const existingInvitation = selectInvitationSession(snapshot);
    if (existingInvitation) {
      invitationSessionId = existingInvitation.id;
      if (!invitationRequested) {
        invitationRequested = true;
      }
    }

    const activeSession = pickActiveSession(snapshot);
    if (activeSession) {
      invitationRequested = false;
      showWelcome();
    } else {
      ui.welcome.hidden = true;
      ui.openButton.hidden = false;
      ui.status.hidden = false;
      if (!invitationRequested) {
        hideInvitation();
        ui.openButton.disabled = false;
        ui.openButton.textContent = 'Connect with Remote Signer';
        ui.status.textContent = 'Connect with a Nostr remote signer to enable uploads.';
      } else {
        void refreshInvitation(snapshot).catch(error => {
          const message = error instanceof Error ? error.message : String(error);
          updateError(ui, message);
        });
      }
    }

    snapshot.sessions.forEach(session => {
      if (sessionNeedsPubkey(session)) {
        const seen = fetchTracker.get(session.id) ?? 0;
        if (session.updatedAt > seen) {
          fetchTracker.set(session.id, session.updatedAt);
          void service.fetchUserPublicKey(session.id);
        }
      }
    });

    const errorSession = snapshot.sessions.find(entry => entry.lastError);
    if (errorSession?.lastError) {
      updateError(ui, errorSession.lastError);
    }
  };

  try {
    await sessionManager.hydrate();
  } catch (error) {
    console.warn('Failed to hydrate NIP-46 sessions', error);
  }

  const initialSnapshot = sessionManager.snapshot();
  const initialInvitation = selectInvitationSession(initialSnapshot);
  if (initialInvitation) {
    invitationRequested = true;
    invitationSessionId = initialInvitation.id;
  }
  handleSnapshot(initialSnapshot);

  sessionManager.onChange(handleSnapshot);

  ui.openButton.addEventListener('click', () => {
    invitationRequested = true;
    updateError(ui, null);
    void refreshInvitation(sessionManager.snapshot(), { forceNew: currentUri !== null });
  });

  ui.copyButton.addEventListener('click', async () => {
    if (!currentUri) return;
    try {
      await navigator.clipboard.writeText(currentUri);
      ui.copyButton.textContent = 'Copied!';
      setTimeout(() => {
        ui.copyButton.textContent = 'Copy link';
      }, 2000);
    } catch (error) {
      updateError(ui, 'Failed to copy link.');
    }
  });
};
