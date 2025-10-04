import { invoke } from '@tauri-apps/api/core'
import { initRemoteSigner } from './remoteSigner'

function isTauri() {
  return typeof (window as any).__TAURI_IPC__ === 'function'
}

;(async () => {
  if (!isTauri()) {
    console.warn('Not running inside Tauri; skipping watcher startup.')
    return
  }
  try {
    await invoke('start_watcher')
    console.log('Watcher started')
  } catch (e) {
    console.error('Failed to start watcher', e)
  }
})()

void initRemoteSigner().catch(error => {
  console.error('Failed to initialise remote signer', error)
})
