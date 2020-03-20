/** ******************************************************************************
 *  (c) 2019 ZondaX GmbH
 *  (c) 2016-2017 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import {
  APP_KEY,
  CHUNK_SIZE,
  CLA,
  ERROR_CODE,
  errorCodeToString,
  INS,
  PAYLOAD_TYPE,
  processErrorResponse,
} from "./common";

const IOV_COIN_TYPE = 234;

function harden(index) {
  // Don't use bitwise operations, which result in signed int32 in JavaScript
  return 0x80000000 + index;
}

export class LedgerApp {
  constructor(transport) {
    if (!transport) {
      throw new Error("Transport has not been defined");
    }

    this.transport = transport;

    transport.decorateAppAPIMethods(this, ["getVersion", "getAddress", "sign"], APP_KEY);
  }

  static serializeBIP32(accountIndex) {
    if (!Number.isInteger(accountIndex)) throw new Error("Input must be an integer");
    if (accountIndex < 0 || accountIndex > 2 ** 31 - 1) throw new Error("Index is out of range");

    const buf = Buffer.alloc(12);
    buf.writeUInt32LE(harden(44), 0);
    buf.writeUInt32LE(harden(IOV_COIN_TYPE), 4);
    buf.writeUInt32LE(harden(accountIndex), 8);
    return buf;
  }

  async getVersion() {
    return this.transport.send(CLA, INS.GET_VERSION, 0, 0).then(response => {
      const errorCodeData = response.slice(-2);
      const errorCode = errorCodeData[0] * 256 + errorCodeData[1];
      return {
        test_mode: response[0] !== 0,
        version: `${response[1]}.${response[2]}.${response[3]}`,
        device_locked: response[4] === 1,
        return_code: errorCode,
        error_message: errorCodeToString(errorCode),
      };
    }, processErrorResponse);
  }

  async getAddress(addressIndex, requireConfirmation = false) {
    const bip32Path = LedgerApp.serializeBIP32(addressIndex);

    const p1 = requireConfirmation ? 1 : 0;

    return this.transport.send(CLA, INS.GET_ADDR_ED25519, p1, 0, bip32Path).then(response => {
      const errorCodeData = response.slice(-2);
      const errorCode = errorCodeData[0] * 256 + errorCodeData[1];
      return {
        pubKey: response.slice(0, 32).toString("hex"),
        address: response.slice(32, response.length - 2).toString("ascii"),
        return_code: errorCode,
        error_message: errorCodeToString(errorCode),
      };
    }, processErrorResponse);
  }

  async signSendChunk(chunkIdx, chunkNum, chunk) {
    let payloadType = PAYLOAD_TYPE.ADD;
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT;
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST;
    }
    return this.transport
      .send(CLA, INS.SIGN_ED25519, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80])
      .then(response => {
        const errorCodeData = response.slice(-2);
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
        let errorMessage = errorCodeToString(returnCode);

        if (returnCode === 0x6a80 || returnCode === 0x6984) {
          errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
        }

        let signature = null;
        if (response.length > 2) {
          signature = response.slice(0, 64);
        }

        return {
          signature,
          return_code: returnCode,
          error_message: errorMessage,
        };
      }, processErrorResponse);
  }

  static prepareChunks(serializedPathBuffer, message) {
    const chunks = [];

    // First chunk (only path)
    chunks.push(serializedPathBuffer);

    const messageBuffer = Buffer.from(message);

    const buffer = Buffer.concat([messageBuffer]);
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE;
      if (i > buffer.length) {
        end = buffer.length;
      }
      chunks.push(buffer.slice(i, end));
    }

    return chunks;
  }

  static signGetChunks(addressIndex, message) {
    const serializedPath = LedgerApp.serializeBIP32(addressIndex);
    return LedgerApp.prepareChunks(serializedPath, message);
  }

  async sign(addressIndex, message) {
    const chunks = LedgerApp.signGetChunks(addressIndex, message);

    return this.signSendChunk(1, chunks.length, chunks[0], [ERROR_CODE.NoError]).then(async response => {
      let result = {
        return_code: response.return_code,
        error_message: response.error_message,
        signature: null,
      };

      for (let i = 1; i < chunks.length; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        result = await this.signSendChunk(1 + i, chunks.length, chunks[i]);
        if (result.return_code !== ERROR_CODE.NoError) {
          break;
        }
      }

      return {
        return_code: result.return_code,
        error_message: result.error_message,
        // ///
        signature: result.signature,
      };
    }, processErrorResponse);
  }
}
