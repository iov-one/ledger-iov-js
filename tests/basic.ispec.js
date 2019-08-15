import LedgerApp from 'index.js';
import TransportNodeHid from '@ledgerhq/hw-transport-node-hid';
import { expect, test } from 'jest';
import { Ed25519, Sha512 } from '@iov/crypto';
import { Encoding } from '@iov/encoding';

const { fromHex, toHex } = Encoding;

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
        expect(version).toEqual(expect.objectContaining({
            test_mode: false,
            major: 0,
            minor: 4,
            patch: 0,
            device_locked: false,
        }));
    });

    test('get address', async () => {
        const app = new LedgerApp(transport);

        const pathAccount = 0x80000000;
        const pathChange = 0x80000000;
        const pathIndex = 0x80000005;

        const response = await app.getAddress(pathAccount, pathChange, pathIndex);
        expect(response.pubKey).toEqual('6ed1781188602d62e9f38f4fb7eb3f51537d88f4589fcead933021d1a8867b05');
        expect(response.address).toEqual('iov1t4n49genjqk2c04fgwmtmtvcampq59rmk66jdg');
    });

    test('show address', async () => {
        jest.setTimeout(60000);

        const app = new LedgerApp(transport);

        const pathAccount = 0x80000000;
        const pathChange = 0x80000000;
        const pathIndex = 0x8000000A;
        const response = await app.getAddress(pathAccount, pathChange, pathIndex, true);

        expect(response.pubKey).toEqual('61d631e7dc190cdf62395ad44ac4495324178ee3975f37f03c523026d952f713');
        expect(response.address).toEqual('iov1m6atk68ge39t24qaahqxsy72ffkus4u7t8tr5a');
    });

    test('sign1', async () => {
        jest.setTimeout(60000);

        const txBlobStr = '00cafe000b696f762d6d61696e6e657400000000000000000a231214bad055e2cbcf'
            + 'fc633e7dc76dc1148d6e9a2debfd1a0b1080c2d72f1a04434153489a03450a0208011214bad055e2'
            + 'cbcffc633e7dc76dc1148d6e9a2debfd1a1400000000000000000000000000000000000000002208'
            + '08011a04434153482a09736f6d652074657874';

        const txBlob = Buffer.from(txBlobStr, 'hex');

        const app = new LedgerApp(transport);

        const pathAccount = 0x80000000;
        const pathChange = 0x80000000;
        const pathIndex = 0x80000000;
        const response = await app.sign(pathAccount, pathChange, pathIndex, txBlob);

        console.log(response);
        expect(response.signature.lentgh).toEqual(64);
    });

    test('sign2_and_verify', async () => {
        jest.setTimeout(60000);

        const txBlobStr = '00cafe000b696f762d6d61696e6e657400000000000000000a231214bad055e2cbcf'
            + 'fc633e7dc76dc1148d6e9a2debfd1a0b1080c2d72f1a04434153489a03450a0208011214bad055e2'
            + 'cbcffc633e7dc76dc1148d6e9a2debfd1a1400000000000000000000000000000000000000002208'
            + '08011a04434153482a09736f6d652074657874';

        const txBlob = Buffer.from(txBlobStr, 'hex');

        const app = new LedgerApp(transport);
        const pathAccount = 0x80000000;
        const pathChange = 0x80000000;
        const pathIndex = 0x80000000;

        const responseAddr = await app.getAddress(pathAccount, pathChange, pathIndex);
        const responseSign = await app.sign(pathAccount, pathChange, pathIndex, txBlob);

        const pubkey = fromHex(responseAddr.pubKey);

        console.log(responseAddr);
        console.log(responseSign);

        // Check signature is valid
        const prehash = new Sha512(txBlob).digest();
        const signature = tou8(responseSign.signature);

        console.log(toHex(signature));

        const valid = await Ed25519.verifySignature(signature, prehash, pubkey);
        expect(valid).toEqual(true);
    });
});
