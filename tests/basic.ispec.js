import LedgerApp from 'index.js';
import TransportNodeHid from '@ledgerhq/hw-transport-node-hid';
import { expect, test } from 'jest';
import { Ed25519, Sha512 } from '@iov/crypto';

function tou8(binary) {
    return new Uint8Array(...binary);
}

describe('Integration tests', () => {
    let transport;

    beforeAll(async () => {
        transport = await TransportNodeHid.create(1000);
    });

    test('get version', async () => {
        const app = new LedgerApp(transport);
        const version = await app.getVersion();
        console.log(version);
    });

    test('get address', async () => {
        const app = new LedgerApp(transport);

        const pathAccount = 0x80000000;
        const pathChange = 0x80000000;
        const pathIndex = 0x80000005;

        const response = await app.getAddress(pathAccount, pathChange, pathIndex);
        console.log(response);

        expect(response.pubKey).toEqual('6ed1781188602d62e9f38f4fb7eb3f51537d88f4589fcead933021d1a8867b05');
        expect(response.address).toEqual('iov1dmghsyvgvqkk960n3a8m06el29fhmz85tz0uatvnxqsar2yx0vzw337ml');
    });

    test('show address', async () => {
        jest.setTimeout(60000);

        const app = new LedgerApp(transport);

        const pathAccount = 0x80000000;
        const pathChange = 0x80000000;
        const pathIndex = 0x8000000A;
        const response = await app.getAddress(pathAccount, pathChange, pathIndex, true);

        console.log(response);

        // FIXME: Address
        expect(response.pubKey).toEqual('61d631e7dc190cdf62395ad44ac4495324178ee3975f37f03c523026d952f713');
        expect(response.address).toEqual('iov1v8trre7uryxd7c3ett2y43zf2vjp0rhrja0n0upu2gczdk2j7uf9xtkyr');
    });

    test('sign1', async () => {
        jest.setTimeout(60000);

        // FIXME: Convert this to a proper pb serialized tx
        const txBlobStr = '0102030405060708091011';

        const txBlob = Buffer.from(txBlobStr, 'hex');

        const app = new LedgerApp(transport);

        const pathAccount = 0x80000000;
        const pathChange = 0x80000000;
        const pathIndex = 0x80000000;
        const response = await app.sign(pathAccount, pathChange, pathIndex, txBlob);

        console.log(response);
    });

    test('sign2_and_verify', async () => {
        jest.setTimeout(60000);

        // FIXME: Convert this to a proper pb serialized tx
        const txBlobStr = '0102030405060708091011';

        const txBlob = Buffer.from(txBlobStr, 'hex');

        const app = new LedgerApp(transport);
        const pathAccount = 0x80000000;
        const pathChange = 0x80000000;
        const pathIndex = 0x80000000;

        const responseAddr = await app.getAddress(pathAccount, pathChange, pathIndex);
        const responseSign = await app.sign(pathAccount, pathChange, pathIndex, txBlob);

        const pubkey = tou8(Buffer.from(responseAddr.pubKey, 'hex'));

        console.log(responseAddr);
        console.log(responseSign);

        // Check signature is valid
        const prehash = new Sha512(txBlob).digest();
        const signature = tou8(responseSign.signature);

        const valid = await Ed25519.verifySignature(signature, prehash, pubkey);
        expect(valid).toEqual(true);
    });
});
