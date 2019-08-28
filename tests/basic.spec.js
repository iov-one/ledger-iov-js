import { LedgerApp } from "..";

describe("LedgerApp", () => {
  describe("serializeBIP32", () => {
    it("returns 3*4 bytes", () => {
      const serialization = LedgerApp.serializeBIP32(0);
      expect(serialization.length).toEqual(12);
    });

    it("returns correct components", () => {
      // Encoding is 3x uint32 as little endian
      expect(LedgerApp.serializeBIP32(0x80000000 + 0x00).toString("hex")).toEqual("2c000080ea00008000000080");
      expect(LedgerApp.serializeBIP32(0x80000000 + 0x01).toString("hex")).toEqual("2c000080ea00008001000080");
      expect(LedgerApp.serializeBIP32(0x80000000 + 0x02).toString("hex")).toEqual("2c000080ea00008002000080");
      expect(LedgerApp.serializeBIP32(0x80000000 + 0x03).toString("hex")).toEqual("2c000080ea00008003000080");
      expect(LedgerApp.serializeBIP32(0x80000000 + 0xff).toString("hex")).toEqual("2c000080ea000080ff000080");
      expect(LedgerApp.serializeBIP32(0x80000000 + 0xffeedd).toString("hex")).toEqual(
        "2c000080ea000080ddeeff80",
      );
      expect(LedgerApp.serializeBIP32(0xffffffff).toString("hex")).toEqual("2c000080ea000080ffffffff");
    });

    it("throws for values out of range", () => {
      expect(() => LedgerApp.serializeBIP32("0")).toThrowError(/Input must be an integer/);
      expect(() => LedgerApp.serializeBIP32(Number.NaN)).toThrowError(/Input must be an integer/);
      expect(() => LedgerApp.serializeBIP32(1.5)).toThrowError(/Input must be an integer/);
      expect(() => LedgerApp.serializeBIP32(Number.POSITIVE_INFINITY)).toThrowError(
        /Input must be an integer/,
      );

      expect(() => LedgerApp.serializeBIP32(-1)).toThrowError(/is out of range/);
      expect(() => LedgerApp.serializeBIP32(0xffffffff + 1)).toThrowError(/is out of range/);
    });
  });
});
