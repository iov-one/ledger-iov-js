import TransportNodeHid from '@ledgerhq/hw-transport-node-hid';
import { expect, test } from 'jest';
import { Ed25519, Sha512 } from '@iov/crypto';
import { Encoding } from '@iov/encoding';
import { LedgerApp } from '..';

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
        expect(version).toEqual(expect.objectContaining({
            test_mode: false,
            major: 0,
            minor: 5,
            patch: 0,
            device_locked: false,
            error_message: 'No errors',
        }));
    });

    test('get address', async () => {
        const app = new LedgerApp(transport);

        const response = await app.getAddress(harden(5));
        expect(response.pubKey).toEqual('05173bf18e8bc4203176be82c89ca9519100fe2cf340cbad239750bd3e3ff668');
        expect(response.address).toEqual('iov1k9rxcg8htk6wcq546p86ksgqhq8fza7h2rkrms');
    });

    test('get multiple addresses', async () => {
        const app = new LedgerApp(transport);

        const response0 = await app.getAddress(harden(0));
        const response1 = await app.getAddress(harden(1));
        const response2 = await app.getAddress(harden(2));
        const response3 = await app.getAddress(harden(3));
        const response4 = await app.getAddress(harden(4));

        // Calculated using Token Finder tool with mnemonic
        // equip will roof matter pink blind book anxiety banner elbow sun young
        expect(response0.pubKey).toEqual('5fe68efa9e7e6373a51f6e519b4ffc7d6330c6cd011d00f6a9663ca82c361bff');
        expect(response1.pubKey).toEqual('385fe5a946e46727297cf7ad0bff7efa637e1c7516ea2fd9f6dc717404494455');
        expect(response2.pubKey).toEqual('c8dca85dd7f1c4f231e46d579199b310975379c37445c664d1be824f088dbe07');
        expect(response3.pubKey).toEqual('5ad1501134fb4ba2f5b1d7c8ca539152d7c31f07a301f6192bb757b3dab52a88');
        expect(response4.pubKey).toEqual('f10ea4323ac84582370321208c71ca77700c85a099991aefc153bc5284c9c025');

        expect(response0.address).toEqual('iov1l678408y7a64cj66s8j64fevmspyfxdmzywuxl');
        expect(response1.address).toEqual('iov1u42wk6lk009ex9t87gt54sn24m2psl4agu2f2k');
        expect(response2.address).toEqual('iov1lxry06n8l760mkthg7sgda48cne4t26l3h8htn');
        expect(response3.address).toEqual('iov10ur3vxhy00el95g5fqthe889z6lzqgr080c0nw');
        expect(response4.address).toEqual('iov12evzw2nds3qzfdrlnka5hx25azaarh3q2527ua');
    });

    test('show address', async () => {
        jest.setTimeout(60000);

        const app = new LedgerApp(transport);

        const response = await app.getAddress(harden(10), true);
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

        const response = await app.sign(harden(0), txBlob);

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
        const accountIndex = harden(0);

        const responseAddr = await app.getAddress(accountIndex);
        const responseSign = await app.sign(accountIndex, txBlob);

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
