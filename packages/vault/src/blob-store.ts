/**
 * Persistence for the vault's opaque blob. The blob is already encrypted, so a
 * blob store only needs to keep an opaque string per account — no crypto here.
 */
export interface BlobStore {
  load(key: string): Promise<string | null>;
  save(key: string, blob: string): Promise<void>;
  remove(key: string): Promise<void>;
}

/** In-memory blob store for tests, Node, and ephemeral use. */
export class InMemoryBlobStore implements BlobStore {
  private readonly blobs = new Map<string, string>();

  async load(key: string): Promise<string | null> {
    return this.blobs.get(key) ?? null;
  }

  async save(key: string, blob: string): Promise<void> {
    this.blobs.set(key, blob);
  }

  async remove(key: string): Promise<void> {
    this.blobs.delete(key);
  }
}

// Minimal IndexedDB shape, declared locally so this file needs no DOM lib (which
// would clash with the Web Crypto types the vault uses elsewhere).
interface IdbRequestLike<T> {
  result: T;
  error: unknown;
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
}
interface IdbOpenRequestLike extends IdbRequestLike<IdbDatabaseLike> {
  onupgradeneeded: (() => void) | null;
}
interface IdbStoreLike {
  get(key: string): IdbRequestLike<unknown>;
  put(value: unknown, key: string): IdbRequestLike<unknown>;
  delete(key: string): IdbRequestLike<unknown>;
}
interface IdbTxLike {
  objectStore(name: string): IdbStoreLike;
}
interface IdbDatabaseLike {
  createObjectStore(name: string): unknown;
  transaction(store: string, mode: string): IdbTxLike;
  close(): void;
}
interface IdbFactoryLike {
  open(name: string, version?: number): IdbOpenRequestLike;
}

function promisify<T>(request: IdbRequestLike<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/**
 * Browser-only {@link BlobStore} backed by IndexedDB, so a wallet can keep the
 * encrypted vault across reloads. Construct it only where `indexedDB` exists.
 */
export class IndexedDbBlobStore implements BlobStore {
  constructor(
    private readonly dbName = 'veil',
    private readonly storeName = 'vault',
  ) {}

  private async withStore<T>(
    mode: 'readonly' | 'readwrite',
    fn: (store: IdbStoreLike) => IdbRequestLike<T>,
  ): Promise<T> {
    const factory = (globalThis as { indexedDB?: IdbFactoryLike }).indexedDB;
    if (!factory) {
      throw new Error('IndexedDbBlobStore requires a browser with IndexedDB');
    }
    const open = factory.open(this.dbName, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(this.storeName);
    const db = await promisify(open);
    try {
      return await promisify(fn(db.transaction(this.storeName, mode).objectStore(this.storeName)));
    } finally {
      db.close();
    }
  }

  async load(key: string): Promise<string | null> {
    const value = await this.withStore('readonly', (store) => store.get(key));
    return typeof value === 'string' ? value : null;
  }

  async save(key: string, blob: string): Promise<void> {
    await this.withStore('readwrite', (store) => store.put(blob, key));
  }

  async remove(key: string): Promise<void> {
    await this.withStore('readwrite', (store) => store.delete(key));
  }
}
