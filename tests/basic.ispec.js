import LedgerApp from 'index.js';
import TransportNodeHid from '@ledgerhq/hw-transport-node-hid';
import { expect, test } from 'jest';
import { Ed25519, Sha512 } from '@iov/crypto';
import { Encoding } from '@iov/encoding';

const { fromHex, toHex } = Encoding;

describe('Integration tests', () => {
    let transport;

    beforeAll(async () => {
        transport = await TransportNodeHid.create(1000);
    });

    test('get version', async () => {
        const app = new LedgerApp(transport);
        const version = await app.getVersion();
        expect(version).toEqual(expect.objectContaining({
            test_mode: false,
            major: 0,
            minor: 6,
            patch: 0,
            device_locked: false,
            error_message: 'No errors',
        }));
    });

    test('get address', async () => {
        const app = new LedgerApp(transport);

        const pathIndex = 0x80000005;

        const response = await app.getAddress(pathIndex);
        expect(response.pubKey).toEqual('05173bf18e8bc4203176be82c89ca9519100fe2cf340cbad239750bd3e3ff668');
        expect(response.address).toEqual('iov1k9rxcg8htk6wcq546p86ksgqhq8fza7h2rkrms');
    });

    test('show address', async () => {
        jest.setTimeout(60000);

        const app = new LedgerApp(transport);

        const pathIndex = 0x8000000A;
        const response = await app.getAddress(pathIndex, true);

        expect(response.pubKey).toEqual('54fb71bc543e9424d8f9df6de1701dd459456e0d1431c1a29f8b5d4e717424af');
        expect(response.address).toEqual('iov1w7n28wf9q297z3mw8lsxvurk6ydnndxrcxcj9h');
    });

    test('sign1', async () => {
        jest.setTimeout(60000);

        const txBlobStr = '00cafe000b696f762d6d61696e6e657400000000000000000a231214bad055e2cbcf'
            + 'fc633e7dc76dc1148d6e9a2debfd1a0b1080c2d72f1a04434153489a03450a0208011214bad055e2'
            + 'cbcffc633e7dc76dc1148d6e9a2debfd1a1400000000000000000000000000000000000000002208'
            + '08011a04434153482a09736f6d652074657874';

        const txBlob = Buffer.from(txBlobStr, 'hex');

        const app = new LedgerApp(transport);

        const pathIndex = 0x80000000;
        const response = await app.sign(pathIndex, txBlob);

        console.log(response);
        expect(response.signature.length).toEqual(64);
    });

    test('sign2_and_verify', async () => {
        jest.setTimeout(60000);

        const txBlobStr = '00cafe000b696f762d6d61696e6e657400000000000000000a231214bad055e2cbcf'
            + 'fc633e7dc76dc1148d6e9a2debfd1a0b1080c2d72f1a04434153489a03450a0208011214bad055e2'
            + 'cbcffc633e7dc76dc1148d6e9a2debfd1a1400000000000000000000000000000000000000002208'
            + '08011a04434153482a09736f6d652074657874';

        const txBlob = Buffer.from(txBlobStr, 'hex');

        const app = new LedgerApp(transport);
        const pathIndex = 0x80000000;

        const responseAddr = await app.getAddress(pathIndex);
        const responseSign = await app.sign(pathIndex, txBlob);

        const pubkey = fromHex(responseAddr.pubKey);

        console.log(responseAddr);
        console.log(responseSign);

        // Check signature is valid
        const prehash = new Sha512(txBlob).digest();
        const signature = new Uint8Array([...responseSign.signature]);

        console.log(toHex(signature));

        const valid = await Ed25519.verifySignature(signature, prehash, pubkey);
        expect(valid).toEqual(true);
    });
});
