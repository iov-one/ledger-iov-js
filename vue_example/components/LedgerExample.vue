<template>
  <div class="Ledger">
    <input id="webusb" v-model="transportChoice" type="radio" value="WebUSB" />
    <label for="webusb">WebUSB</label>
    <input id="u2f" v-model="transportChoice" type="radio" value="U2F" />
    <label for="u2f">U2F</label>
    <br />
    <!--
        Commands
    -->
    <button @click="getVersion">
      Get Version
    </button>

    <button @click="getAddress">
      Get Address and Pubkey
    </button>

    <button @click="showAddress">
      Show Address and Pubkey
    </button>

    <button @click="signExampleTx">
      Sign Example TX
    </button>
    <!--
        Commands
    -->
    <ul id="ledger-status">
      <li v-for="item in ledgerStatus" :key="item.index">
        {{ item.msg }}
      </li>
    </ul>
  </div>
</template>

<script>
// eslint-disable-next-line import/no-extraneous-dependencies
import TransportWebUSB from "@ledgerhq/hw-transport-webusb";
// eslint-disable-next-line import/no-extraneous-dependencies
import TransportU2F from "@ledgerhq/hw-transport-u2f";
import { LedgerApp } from "../../src";

const txBlobStr =
  "00cafe000b696f762d6d61696e6e657400000000000000070a2312145ae2c58796b0ad48ffe7602eac3353488c859a2b1a0b1080c2d72f1a0" +
  "443415348220800000000000000012208000000000000007b220800000000000001c722080000000000000b3d9a03c2010a02080112148787" +
  "878787878787aaaaaaaaaaaaaaaa999999991a14020daec62066ec82a5a1b40378d87457ed88e4fc220d08081080d293ad031a03494f562a8" +
  "001412076657279206c6f6e67206d656d6f206c6f72656d20697073756d206c6f72656d20697073756d2e20412076657279206c6f6e67206d" +
  "656d6f206c6f72656d20697073756d206c6f72656d20697073756d2e20412076657279206c6f6e67206d656d6f206c6f72656d20697073756" +
  "d206c6f72656d20697073756d21213131";

export default {
  name: "Ledger",
  props: {},
  data() {
    return {
      deviceLog: [],
      transportChoice: "WebUSB",
    };
  },
  computed: {
    ledgerStatus() {
      return this.deviceLog;
    },
  },
  methods: {
    log(msg) {
      this.deviceLog.push({
        index: this.deviceLog.length,
        msg,
      });
    },
    async getTransport() {
      let transport = null;

      this.log(`Trying to connect via ${this.transportChoice}...`);
      if (this.transportChoice === "WebUSB") {
        try {
          transport = await TransportWebUSB.create();
        } catch (e) {
          this.log(e);
        }
      }

      if (this.transportChoice === "U2F") {
        try {
          transport = await TransportU2F.create(10000);
        } catch (e) {
          this.log(e);
        }
      }

      return transport;
    },
    async getVersion() {
      this.deviceLog = [];

      // Given a transport (U2F/HIF/WebUSB) it is possible instantiate the app
      const transport = await this.getTransport();
      const app = new LedgerApp(transport);

      // now it is possible to access all commands in the app
      const response = await app.getVersion();
      if (response.return_code !== 0x9000) {
        this.log(`Error [${response.return_code}] ${response.error_message}`);
        return;
      }

      this.log("Response received!");
      this.log(response);
      this.log("...");
      this.log(`App Version ${response.version}`);
      this.log(`Device Locked: ${response.device_locked}`);
      this.log(`Test mode: ${response.test_mode}`);
    },
    async getAddress() {
      this.deviceLog = [];

      // Given a transport (U2F/HIF/WebUSB) it is possible instantiate the app
      const transport = await this.getTransport();
      const app = new LedgerApp(transport);

      // now it is possible to access all commands in the app
      const accountIndex = 0;
      const response = await app.getAddress(accountIndex, false);
      if (response.return_code !== 0x9000) {
        this.log(`Error [${response.return_code}] ${response.error_message}`);
        return;
      }

      this.log("Response received!");
      this.log(response);
      this.log("...");
      this.log(`PubKey ${response.pubKey}`);
      this.log(`Address: ${response.address}`);
      this.log("...");
    },
    async showAddress() {
      this.deviceLog = [];

      // Given a transport (U2F/HIF/WebUSB) it is possible instantiate the app
      const transport = await this.getTransport();
      const app = new LedgerApp(transport);

      // now it is possible to access all commands in the app
      this.log("Please click in the device");
      const accountIndex = 0;
      const response = await app.getAddress(accountIndex, true);
      if (response.return_code !== 0x9000) {
        this.log(`Error [${response.return_code}] ${response.error_message}`);
        return;
      }

      this.log("Response received!");
      this.log(response);
      this.log("...");
      this.log(`PubKey ${response.pubKey}`);
      this.log(`Address: ${response.address}`);
      this.log("...");
    },
    async signExampleTx() {
      this.deviceLog = [];

      // Given a transport (U2F/HIF/WebUSB) it is possible instantiate the app
      const transport = await this.getTransport();
      const app = new LedgerApp(transport);

      // now it is possible to access all commands in the app
      const message = Buffer.from(txBlobStr, "hex");
      const accountIndex = 0;
      const response = await app.sign(accountIndex, message);

      this.log("Response received!");
      this.log(response);
      this.log("...");
      this.log(`Signature: ${response.signature.toString("hex")}`);
      this.log("...");
      this.log("Full response:");
      this.log(response);
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}

button {
  padding: 5px;
  font-weight: bold;
  font-size: medium;
}

ul {
  padding: 10px;
  text-align: left;
  alignment: left;
  list-style-type: none;
  background: black;
  font-weight: bold;
  color: greenyellow;
}
</style>
