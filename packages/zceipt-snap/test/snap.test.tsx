import { expect } from '@jest/globals';
import { installSnap } from '@metamask/snaps-jest';
import { execFileSync } from 'child_process';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const ORIGIN = 'http://localhost:5320';
const live = (...args: string[]) => execFileSync('node', [resolve(__dirname, 'live.mjs'), ...args], { encoding: 'utf8', maxBuffer: 1 << 26 });

describe('Zceipt snap', () => {
  it('refuses sites not on its list', async () => {
    const { request } = await installSnap();
    const r = await request({ method: 'getViewingKey', origin: 'https://evil.example' });
    expect(r).toRespondWithError(expect.objectContaining({ message: expect.stringContaining('evil.example') }));
  });

  it('shares nothing when the window is closed', async () => {
    const { request } = await installSnap();
    const r = request({ method: 'getViewingKey', origin: ORIGIN, params: { network: 'test' } });
    const ui = await r.getInterface();
    await ui.cancel();
    expect(await r).toRespondWithError(expect.objectContaining({ message: 'User rejected the request.' }));
  });

  it("opens MetaMask's own Zcash keys when no phrase is given", async () => {
    const { request } = await installSnap();
    const r = request({ method: 'getViewingKey', origin: ORIGIN, params: { network: 'test' } });
    const ui = await r.getInterface();
    await ui.clickElement('shareButton');
    const res = (await r).response as { result: { viewingKey: string; imported: boolean } };
    expect(res.result.viewingKey).toMatch(/^uviewtest1/u);
    expect(res.result.imported).toBe(false);
  });

  // Live, on testnet: ZCEIPT_SNAP_PHRASE_FILE (a throwaway wallet's phrase), ZCEIPT_SNAP_TX
  // (`txid:height:birthday` of a payment it made).
  const phraseFile = process.env.ZCEIPT_SNAP_PHRASE_FILE;
  (phraseFile ? it : it.skip)('imports a wallet, shares its viewing key, and signs a receipt that verifies', async () => {
    const [txid, height, birthday] = (process.env.ZCEIPT_SNAP_TX ?? '').split(':');
    const { request } = await installSnap();

    const share = request({ method: 'getViewingKey', origin: ORIGIN, params: { network: 'test' } });
    const form = await share.getInterface();
    await form.typeInField('phrase', readFileSync(phraseFile!, 'utf8').trim());
    await form.typeInField('birthday', birthday);
    await form.clickElement('shareButton');
    const shared = ((await share).response as { result: { viewingKey: string; birthday: number; imported: boolean } }).result;
    expect(shared.imported).toBe(true);
    expect(shared.birthday).toBe(Number(birthday));

    // The site's part: proofs from the viewing key alone.
    const prepared = live('prove', shared.viewingKey, String(shared.birthday), txid, height);
    expect(prepared).toMatch(/^zip311u1/u);

    const sign = request({ method: 'signReceipt', origin: ORIGIN, params: { prepared } });
    const confirm = await sign.getInterface();
    // The dialog names the payment from the receipt itself.
    expect(JSON.stringify(confirm.content)).toContain(txid);
    await confirm.ok();
    const { receipt } = ((await sign).response as { result: { receipt: string } }).result;
    expect(receipt).toMatch(/^zip311r1/u);

    const verdict = JSON.parse(live('verify', receipt, height));
    expect(verdict.txid).toBe(txid);
    expect(verdict.message).toBe('Order 2001 (MetaMask)');
    // Asked again, the snap remembers the wallet and doesn't ask for the phrase.
    const again = request({ method: 'getViewingKey', origin: ORIGIN, params: { network: 'test' } });
    const ui2 = await again.getInterface();
    expect(JSON.stringify(ui2.content)).not.toContain('"phrase"');
    await ui2.clickElement('shareButton');
    expect(((await again).response as { result: { viewingKey: string } }).result.viewingKey).toBe(shared.viewingKey);
  });
});
