import TransportNodeHid from '@ledgerhq/hw-transport-node-hid';
import { expect, test } from 'jest';
import { Ed25519, Sha512 } from '@iov/crypto';
import { Encoding } from '@iov/encoding';
import LedgerApp from '..';

const { fromHex, toHex } = Encoding;

function harden(index) {
    // Don't use bitwise operations, which result in signed int32 in JavaScript.
    // Addition works well for small numbers.
    return 0x80000000 + index;
}

describe('Integration tests', () => {
    let transport;

    beforeAll(async () => {
        transport = await TransportNodeHid.create(1000);
    });

    test('get version', async () => {
        const app = new LedgerApp(transport);
        const version = await app.getVersion();
        expect(version)
            .toEqual(expect.objectContaining({
                major: 0,
                minor: 7,
                patch: 0,
                device_locked: false,
                error_message: 'No errors',
            }));
    });

    test('get address', async () => {
        const app = new LedgerApp(transport);
        const version = await app.getVersion();

        const pathIndex = 0x80000005;
        const response = await app.getAddress(pathIndex);

        expect(response.pubKey)
            .toEqual('05173bf18e8bc4203176be82c89ca9519100fe2cf340cbad239750bd3e3ff668');

        // Depending on the app version, we can get mainnet or testnet addresses
        if (version.test_mode) {
            expect(response.address)
                .toEqual('tiov1k9rxcg8htk6wcq546p86ksgqhq8fza7hykl8mp');
        } else {
            expect(response.address)
                .toEqual('iov1k9rxcg8htk6wcq546p86ksgqhq8fza7h2rkrms');
        }
    });

    test('show address', async () => {
        jest.setTimeout(60000);

        const app = new LedgerApp(transport);
        const version = await app.getVersion();

        const pathIndex = 0x8000000A;
        const response = await app.getAddress(pathIndex, true);

        expect(response.pubKey)
            .toEqual('54fb71bc543e9424d8f9df6de1701dd459456e0d1431c1a29f8b5d4e717424af');

        // Depending on the app version, we can get mainnet or testnet addresses
        if (version.test_mode) {
            expect(response.address)
                .toEqual('tiov1w7n28wf9q297z3mw8lsxvurk6ydnndxrkn3k9x');
        } else {
            expect(response.address)
                .toEqual('iov1w7n28wf9q297z3mw8lsxvurk6ydnndxrcxcj9h');
        }
    });

    test('sign_and_verify_testnet', async () => {
        jest.setTimeout(60000);

        const txBlobStr = '00cafe000b696f762d6c6f76656e657400000000000000009a03380a020801121473'
            + 'f16e71d0878f6ad26531e174452aec9161e8d41a1400000000000000000000000000000000000000'
            + '0022061a0443415348';

        const txBlob = Buffer.from(txBlobStr, 'hex');

        const app = new LedgerApp(transport);
        const version = await app.getVersion();

        const pathIndex = 0x80000000;

        const responseAddr = await app.getAddress(pathIndex);
        const pubkey = fromHex(responseAddr.pubKey);

        const responseSign = await app.sign(pathIndex, txBlob);
        console.log(responseSign);

        if (!version.test_mode) {
            expect(responseSign.return_code)
                .toEqual(27012);
            expect(responseSign.error_message)
                .toEqual('Data is invalid');
            return;
        }

        // Check signature is valid
        const prehash = new Sha512(txBlob).digest();
        const signature = new Uint8Array([...responseSign.signature]);

        console.log(toHex(signature));

        const valid = await Ed25519.verifySignature(signature, prehash, pubkey);
        expect(valid)
            .toEqual(true);
    });

    test('sign_and_verify_mainnet', async () => {
        jest.setTimeout(60000);

        const txBlobStr = '00cafe000b696f762d6d61696e6e6574001fffffffffffff0a231214bad055e2cb'
            + 'cffc633e7dc76dc1148d6e9a2debfd1a0b1080c2d72f1a04434153489a03560a0208011214bad0'
            + '55e2cbcffc633e7dc76dc1148d6e9a2debfd1a14020daec62066ec82a5a1b40378d87457ed88e4fc'
            + '220d0807108088debe011a03494f562a1574657874207769746820656d6f6a693a20f09f908e';

        const txBlob = Buffer.from(txBlobStr, 'hex');

        const app = new LedgerApp(transport);
        const version = await app.getVersion();

        const pathIndex = 0x80000000;

        const responseAddr = await app.getAddress(pathIndex);
        const pubkey = fromHex(responseAddr.pubKey);

        const responseSign = await app.sign(pathIndex, txBlob);
        console.log(responseSign);

        if (version.test_mode) {
            expect(responseSign.return_code)
                .toEqual(27012);
            expect(responseSign.error_message)
                .toEqual('Data is invalid');
            return;
        }

        // Check signature is valid
        const prehash = new Sha512(txBlob).digest();
        const signature = new Uint8Array([...responseSign.signature]);

        console.log(toHex(signature));

        const valid = await Ed25519.verifySignature(signature, prehash, pubkey);
        expect(valid)
            .toEqual(true);
    });
});
