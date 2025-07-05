import {
  Address,
  beginCell,
  Cell,
  contractAddress,
  loadStateInit,
} from "@ton/core";
import { sha256 } from "@ton/crypto";
import { Buffer } from "buffer";
import nacl from "tweetnacl";
import crc32 from "crc-32";

// Интерфейсы для sign-data
export interface CheckSignDataRequestDto {
  signature: string;
  address: string;
  timestamp: number;
  domain: string;
  payload: SignDataPayload;
  public_key: string;
  walletStateInit: string;
}

export interface SignDataPayloadText {
  type: 'text';
  text: string;
}

export interface SignDataPayloadBinary {
  type: 'binary';
  bytes: string;
}

export interface SignDataPayloadCell {
  type: 'cell';
  cell: string;
  schema: string;
}

export type SignDataPayload = SignDataPayloadText | SignDataPayloadBinary | SignDataPayloadCell;

const allowedDomains = ["pikromachess-tma-patterns-47ab.twc1.net", "localhost:5173", "localhost:3000"];
const validAuthTime = 15 * 60; // 15 minutes

export class SignDataService {
  /**
   * Verifies sign-data signature.
   */
  public async checkSignData(
    payload: CheckSignDataRequestDto,
    getWalletPublicKey: (address: string) => Promise<Buffer | null>
  ): Promise<boolean> {
    try {
      const {
        signature,
        address,
        timestamp,
        domain,
        payload: signDataPayload,
      } = payload;

      console.log('🔍 Проверяем sign-data:', {
        address,
        domain,
        timestamp,
        payloadType: signDataPayload.type,
        signatureLength: signature.length
      });

      // Check domain
      if (!allowedDomains.includes(domain)) {
        console.warn('❌ Недопустимый домен:', domain);
        return false;
      }

      // Check timestamp
      const now = Math.floor(Date.now() / 1000);
      if (now - validAuthTime > timestamp) {
        console.warn('❌ Подпись устарела:', { now, timestamp, diff: now - timestamp });
        return false;
      }

      // Parse address
      const parsedAddr = Address.parse(address);
      console.log('✅ Адрес распарсен:', parsedAddr.toString());

      // Get public key from wallet
      let publicKey = await getWalletPublicKey(address);
      if (!publicKey) {
        console.warn('❌ Не удалось получить публичный ключ для адреса:', address);
        return false;
      }

      console.log('✅ Публичный ключ получен, длина:', publicKey.length);

      // Create hash based on payload type
      const finalHash =
        signDataPayload.type === "cell"
          ? this.createCellHash(signDataPayload as SignDataPayloadCell, parsedAddr, domain, timestamp)
          : await this.createTextBinaryHash(
              signDataPayload as SignDataPayloadText | SignDataPayloadBinary,
              parsedAddr,
              domain,
              timestamp
            );

      console.log('✅ Хеш создан, длина:', finalHash.length);

      // Verify Ed25519 signature
      const isValid = nacl.sign.detached.verify(
        new Uint8Array(finalHash),
        new Uint8Array(Buffer.from(signature, "base64")),
        new Uint8Array(publicKey)
      );

      console.log('🔐 Результат проверки подписи:', isValid);
      return isValid;

    } catch (e) {
      console.error("❌ Ошибка проверки sign-data:", e);
      return false;
    }
  }

  /**
   * Creates hash for text or binary payload.
   */
  private async createTextBinaryHash(
    payload: SignDataPayloadText | SignDataPayloadBinary,
    parsedAddr: Address,
    domain: string,
    timestamp: number
  ): Promise<Buffer> {
    console.log('🔨 Создаем хеш для text/binary payload:', {
      type: payload.type,
      workchain: parsedAddr.workChain,
      domain,
      timestamp
    });

    // Create workchain buffer
    const wcBuffer = Buffer.alloc(4);
    wcBuffer.writeInt32BE(parsedAddr.workChain);

    // Create domain buffer
    const domainBuffer = Buffer.from(domain, "utf8");
    const domainLenBuffer = Buffer.alloc(4);
    domainLenBuffer.writeUInt32BE(domainBuffer.length);

    // Create timestamp buffer
    const tsBuffer = Buffer.alloc(8);
    tsBuffer.writeBigUInt64BE(BigInt(timestamp));

    // Create payload buffer
    const typePrefix = payload.type === "text" ? "txt" : "bin";
    const content = payload.type === "text" ? payload.text : payload.bytes;
    const encoding = payload.type === "text" ? "utf8" : "base64";

    const payloadPrefix = Buffer.from(typePrefix);
    const payloadBuffer = Buffer.from(content, encoding);
    const payloadLenBuffer = Buffer.alloc(4);
    payloadLenBuffer.writeUInt32BE(payloadBuffer.length);

    // Build message
    const message = Buffer.concat([
      Buffer.from([0xff, 0xff]),
      Buffer.from("ton-connect/sign-data/"),
      wcBuffer,
      parsedAddr.hash,
      domainLenBuffer,
      domainBuffer,
      tsBuffer,
      payloadPrefix,
      payloadLenBuffer,
      payloadBuffer,
    ]);

    console.log('📏 Размер сообщения для хеширования:', message.length);

    // Hash message with sha256
    const hash = await sha256(message);
    return Buffer.from(hash);
  }

  /**
   * Creates hash for Cell payload according to TON Connect specification.
   */
  private createCellHash(
    payload: SignDataPayloadCell,
    parsedAddr: Address,
    domain: string,
    timestamp: number
  ): Buffer {
    console.log('🔨 Создаем хеш для cell payload:', {
      schema: payload.schema,
      workchain: parsedAddr.workChain,
      domain,
      timestamp
    });

    const cell = Cell.fromBase64(payload.cell);
    const schemaHash = crc32.buf(Buffer.from(payload.schema, "utf8")) >>> 0;

    // Encode domain in DNS-like format
    const encodedDomain = this.encodeDomainDnsLike(domain);

    const message = beginCell()
      .storeUint(0x75569022, 32) // prefix
      .storeUint(schemaHash, 32) // schema hash
      .storeUint(timestamp, 64) // timestamp
      .storeAddress(parsedAddr) // user wallet address
      .storeStringRefTail(encodedDomain.toString("utf8")) // app domain
      .storeRef(cell) // payload cell
      .endCell();

    return Buffer.from(message.hash());
  }

  /**
   * Encodes domain name in DNS-like format.
   */
  private encodeDomainDnsLike(domain: string): Buffer {
    const parts = domain.split(".").reverse();
    const encoded: number[] = [];

    for (const part of parts) {
      for (let i = 0; i < part.length; i++) {
        encoded.push(part.charCodeAt(i));
      }
      encoded.push(0);
    }

    return Buffer.from(encoded);
  }
}