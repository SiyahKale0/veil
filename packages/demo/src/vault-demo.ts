import { randomUUID } from 'node:crypto';
import type { PresentationRequest } from 'veil-core';
import {
  generateKeyPair,
  type MembershipClaims,
  SdJwtIssuer,
  SdJwtPresenter,
  SdJwtVerifier,
} from 'veil-sd-jwt';
import { EncryptedVaultStore, InMemoryVaultSync, WrongPasswordError } from 'veil-vault';

const PASSWORD = 'correct horse battery staple';

async function main(): Promise<void> {
  // Issue a credential bound to the holder's key.
  const issuerKeys = await generateKeyPair();
  const holderKeys = await generateKeyPair();
  const issuer = new SdJwtIssuer('https://issuer.veil.dev', issuerKeys.privateKey);
  const claims: MembershipClaims = {
    user_id: 'u_8f3a21',
    email: 'ada@example.com',
    tier: 'gold',
    category_sports: 'climbing',
  };
  const credential = await issuer.issue(claims, holderKeys.publicKey);

  // Device A: keep the credential in an encrypted vault and sync the blob.
  const deviceA = await EncryptedVaultStore.create(PASSWORD);
  await deviceA.put('membership', credential);
  const sync = new InMemoryVaultSync();
  await sync.upload('ada', await deviceA.export());
  console.log('1. Device A encrypted the credential and synced the vault.\n');

  // What the sync server can see is an opaque blob and nothing more.
  const onServer = sync.storedBlob('ada') ?? '';
  console.log('2. What the server can see:');
  console.log(`   ${onServer.slice(0, 72)}...`);
  console.log(`   contains "ada@example.com"? ${onServer.includes('ada@example.com')}\n`);

  // The wrong password cannot open the vault.
  try {
    await EncryptedVaultStore.unlock('hunter2', onServer);
  } catch (error) {
    if (error instanceof WrongPasswordError) {
      console.log('3. Wrong password was rejected.\n');
    } else {
      throw error;
    }
  }

  // Device B: restore from the synced blob with the right password.
  const blob = await sync.download('ada');
  if (!blob) throw new Error('nothing to restore');
  const deviceB = await EncryptedVaultStore.unlock(PASSWORD, blob);
  const restored = await deviceB.get('membership');
  if (!restored) throw new Error('restore failed');
  console.log('4. Device B unlocked the vault and restored the credential.\n');

  // The restored credential still works end to end.
  const request: PresentationRequest = {
    verifierId: 'https://gym.example',
    requestedClaims: ['category_sports'],
    nonce: randomUUID(),
    audience: 'https://gym.example',
  };
  const presenter = new SdJwtPresenter(holderKeys.privateKey);
  const verifier = new SdJwtVerifier(issuerKeys.publicKey);
  const presentation = await presenter.present(request, restored);
  const disclosed = await verifier.verify(presentation, request);
  console.log('5. Restored credential presented and verified:');
  console.log(`   category_sports = ${String(disclosed.category_sports)}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
