// Zceipt for MetaMask. A site asks for a viewing key (to find the wallet's payments and make the
// proofs) and for a signature on a prepared receipt; MetaMask shows what each one gives away and
// nothing happens without a click. The seed never leaves the snap.
//
// The wallet is either one imported here (a seed phrase from Zashi, Zingo, zcash-devtool…, kept
// in MetaMask's encrypted snap state) or MetaMask's own Zcash keys: the BIP 44 entropy at coin
// type 133 used as the ZIP 32 seed, the same wallet ChainSafe's Zcash snap opens.
import type { OnRpcRequestHandler, OnUserInputHandler } from '@metamask/snaps-sdk';
import { UserInputEventType } from '@metamask/snaps-sdk';
import { Bold, Box, Button, Copyable, Divider, Field, Form, Heading, Input, Text } from '@metamask/snaps-sdk/jsx';
import { initSync, describe_prepared, sign_with_seed, viewing_key_from_seed } from '../../zceipt/pkg/zceipt_wasm.js';
import wasmUrl from '../../zceipt/pkg/zceipt_wasm_bg.wasm';
import { seedFromPhrase } from './phrase';

type State = { seed?: string; birthday?: number };
type Network = 'test' | 'main';

let ready = false;
function wasm() {
  if (!ready) {
    // Inlined by the bundler as a data: URL.
    const b64 = (wasmUrl as unknown as string).split(',')[1];
    initSync({ module: Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)) });
    ready = true;
  }
}

const hex = (u8: Uint8Array) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => Uint8Array.from(s.match(/../gu) ?? [], (h) => parseInt(h, 16));

async function getState(): Promise<State> {
  return ((await snap.request({ method: 'snap_manageState', params: { operation: 'get' } })) as State | null) ?? {};
}

async function setState(state: State) {
  await snap.request({ method: 'snap_manageState', params: { operation: 'update', newState: state } });
}

async function metamaskSeed(): Promise<Uint8Array> {
  const node = (await snap.request({ method: 'snap_getBip44Entropy', params: { coinType: 133 } })) as { privateKey?: string };
  const key = (node.privateKey ?? '').replace(/^0x/u, '');
  if (!/^[0-9a-f]{64}$/iu.test(key)) throw new Error('MetaMask returned no Zcash entropy');
  return unhex(key);
}

async function seedOf(state: State) {
  return state.seed ? unhex(state.seed) : metamaskSeed();
}

// A form in a MetaMask window; resolves with its values, or null if it was closed.
async function form(ui: JSX.Element): Promise<Record<string, string | null> | null> {
  const id = await snap.request({ method: 'snap_createInterface', params: { ui } });
  return (await snap.request({ method: 'snap_dialog', params: { id } })) as Record<string, string | null> | null;
}

export const onUserInput: OnUserInputHandler = async ({ id, event }) => {
  if (event.type === UserInputEventType.FormSubmitEvent) {
    await snap.request({ method: 'snap_resolveInterface', params: { id, value: event.value } });
  }
};

async function getViewingKey(origin: string, network: Network) {
  wasm();
  let state = await getState();
  const fresh = !state.seed && state.birthday === undefined;
  // The site picks the network: name it, so a key for the wrong chain is refused here.
  const chain = network === 'main' ? 'mainnet' : 'testnet';
  const values = await form(
    <Form name="share">
      <Box>
        <Heading>Share a {chain} viewing key</Heading>
        <Text>
          <Bold>{origin}</Bold> can then find this wallet's {chain} payments and make receipt proofs. A viewing key can't spend.
        </Text>
        {fresh ? (
          <Box>
            <Divider />
            <Field label="Seed phrase (empty: your MetaMask Zcash wallet)">
              <Input name="phrase" type="password" placeholder="24 words" />
            </Field>
            <Field label="Wallet birthday (block)">
              <Input name="birthday" type="number" placeholder="Block the wallet was created at" />
            </Field>
          </Box>
        ) : null}
      </Box>
      <Button type="submit" name="shareButton">Share</Button>
    </Form>,
  );
  if (!values) throw new Error('User rejected the request.');
  if (fresh) {
    const phrase = (values.phrase ?? '').trim();
    const birthday = Number(values.birthday);
    state = {
      ...(phrase ? { seed: hex(await seedFromPhrase(phrase)) } : {}),
      ...(Number.isInteger(birthday) && birthday > 0 ? { birthday } : {}),
    };
    await setState(state);
  }
  const viewingKey = viewing_key_from_seed(await seedOf(state), network === 'test', 0);
  return { viewingKey, birthday: state.birthday ?? null, imported: Boolean(state.seed) };
}

async function signReceipt(origin: string, prepared: string) {
  wasm();
  // What gets revealed is read from the receipt itself, not from the site's description of it.
  const d = JSON.parse(describe_prepared(prepared)) as {
    network: string; txid: string; message: string; outputs_with_memo: number; outputs_without_memo: number; spends: number;
    opened: { index: number; recipient: string; zatoshis: number }[];
  };
  const outputs = d.outputs_with_memo + d.outputs_without_memo;
  const unit = d.network === 'mainnet' ? 'ZEC' : 'TAZ';
  const amount = (z: number) => `${(z / 1e8).toFixed(8).replace(/0+$/u, '').replace(/\.$/u, '')} ${unit}`;
  const ok = await snap.request({
    method: 'snap_dialog',
    params: {
      type: 'confirmation',
      content: (
        <Box>
          <Heading>Sign a payment receipt</Heading>
          <Text>
            <Bold>{origin}</Bold> asks you to prove this {d.network} payment.
          </Text>
          <Copyable value={d.txid} />
          <Divider />
          <Text>
            It reveals {String(outputs)} output{outputs === 1 ? '' : 's'} you sent (recipient and amount
            {d.outputs_with_memo ? ', with memo' : ''}) and that you spent {String(d.spends)} note{d.spends === 1 ? '' : 's'}. Nothing else about your wallet.
          </Text>
          {d.message ? <Text>Message: {d.message}</Text> : null}
          {(d.opened ?? []).map((o) => (
            <Box key={String(o.index)}>
              <Text>{amount(o.zatoshis)} to</Text>
              <Copyable value={o.recipient} />
            </Box>
          ))}
        </Box>
      ),
    },
  });
  if (!ok) throw new Error('User rejected the request.');
  return { receipt: sign_with_seed(prepared, await seedOf(await getState()), 0) };
}

async function forget(origin: string) {
  const ok = await snap.request({
    method: 'snap_dialog',
    params: { type: 'confirmation', content: <Box><Heading>Forget the wallet?</Heading><Text>{origin} asks to remove the wallet imported into Zceipt.</Text></Box> },
  });
  if (!ok) throw new Error('User rejected the request.');
  await setState({});
  return true;
}

// The manifest's allowedOrigins is what MetaMask enforces; this repeats it so a manifest edit
// alone can't open the snap to other sites.
const ORIGINS = ['https://zceipt.xyz', 'https://www.zceipt.xyz', 'http://localhost:5320', 'http://127.0.0.1:5320', 'http://127.0.0.1:8731'];

export const onRpcRequest: OnRpcRequestHandler = async ({ origin, request }) => {
  if (!ORIGINS.includes(origin)) throw new Error(`${origin} may not use Zceipt's MetaMask snap`);
  const params = (request.params ?? {}) as Record<string, unknown>;
  switch (request.method) {
    case 'getViewingKey':
      return getViewingKey(origin, params.network === 'main' ? 'main' : 'test');
    case 'signReceipt':
      if (typeof params.prepared !== 'string' || !params.prepared.startsWith('zip311u1')) throw new Error('prepared must be a zip311u1… prepared receipt');
      return signReceipt(origin, params.prepared);
    case 'forget':
      return forget(origin);
    default:
      throw new Error('Method not found.');
  }
};
