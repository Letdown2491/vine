import { SimplePool, type Event as NostrToolsEvent, type Filter } from 'nostr-tools';

import type { NostrEvent, NostrFilter, TransportConfig } from './types';

const normalizeRelays = (relays: string[]): string[] => {
  const unique = new Set<string>();
  relays.forEach(relay => {
    if (typeof relay !== 'string') return;
    const trimmed = relay.trim();
    if (!trimmed) return;
    unique.add(trimmed.replace(/\/$/, ''));
  });
  return Array.from(unique);
};

export const createSimplePoolTransport = (getRelayUrls: () => string[]): TransportConfig => {
  const pool = new SimplePool();

  const publish = async (event: NostrEvent) => {
    const targets = normalizeRelays(event.relays?.length ? event.relays : getRelayUrls());
    if (!targets.length) {
      throw new Error('No relays configured for NIP-46 publish');
    }
    const promises = pool.publish(targets, event as unknown as NostrToolsEvent);
    let publishError: Error | null = null;
    await Promise.all(
      promises.map(p =>
        p.catch(error => {
          publishError = error instanceof Error ? error : new Error(String(error));
        })
      )
    );
    if (publishError) {
      throw publishError;
    }
  };

  const subscribe = (filters: NostrFilter[], handler: (event: NostrEvent) => void) => {
    const relayUrls = normalizeRelays(getRelayUrls());
    if (!relayUrls.length) {
      console.warn('No relays configured for NIP-46 subscription');
      return () => undefined;
    }
    const closer = pool.subscribeMany(relayUrls, filters as unknown as Filter[], {
      onevent: event => {
        handler(event as unknown as NostrEvent);
      },
    });
    return () => {
      closer.close();
    };
  };

  return {
    publish,
    subscribe,
  };
};

