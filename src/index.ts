import { V4, errors } from 'paseto';
import NodeCache from 'node-cache';

type AttestationPayload = {
  slid: string;
  sub: string | undefined;
  result: string | undefined;
  extrefs: Array<object>;
}

interface DecodeParameters {
  ignoreExpiry?: boolean;
}

class AttestationError extends Error {
  constructor(
    private originalError: Error) {
    super(originalError.message);
    // Set the prototype explicitly.
    Object.setPrototypeOf(this, AttestationError.prototype);
  }

  // TODO checkers for whether token expired, redeemed etc.
}

class Attestation {
  constructor(
    private readonly payload: AttestationPayload
  ) {

  }

  public getSlid(): string | undefined {
    return this.payload?.slid;
  }

  public isAuthenticated(): boolean {
    return this.payload?.result == "AUTHENTIC";
  }

  public isFraud(): boolean {
    return this.payload?.result== "COUNTERFEIT"

  }
}

class AttestationManager  {
  private cache: NodeCache  = new NodeCache();
  private keyServerUrl: string = "https://sip-keys.authenticvision.com/v4";

  constructor() {

  }

  public addKey(keyId: string, publicKey: string) {
    this.cache.set(keyId, publicKey);
  }

  private async getSipKeyHttps(keyId:string): Promise<string> {
    const cachedKey = this.cache.get<string>(keyId);
    if (cachedKey) {
       return cachedKey;
    }

    const response = await fetch(`${this.keyServerUrl}/${keyId}`);
    const key = await response.text();
    this.cache.set(keyId, key);
    return key;
  }


  public activateDevelopmentMode(): void {
    this.keyServerUrl = "https://api.metaanchor.io/api/v1/attestation/keys/v4"
  }


  public async decode(token: string, params?: DecodeParameters): Promise<Attestation> {
    try {
      const parsedToken = JSON.parse(Buffer.from(token.split('.')[3], 'base64').toString('utf-8'));

      // Key retrieval
 
      const pubkid = parsedToken.kid;
      const pubKey = await this.getSipKeyHttps(pubkid); // FIXME error handling!      
      
      // For demo-purposes, decode it even if expired
      //const rawPayload = (await V4.verify(token, pubKey!, { ignoreExp: true, complete: true }))?.payload as AttestationTokenPayload;
      
      const validatedPayload = await V4.verify(token, pubKey!, { ignoreExp: params?.ignoreExpiry, complete: true });
      const attestation = new Attestation(validatedPayload?.payload as AttestationPayload); 

      return attestation;
    } catch (error) {
      // Package into a typed error, which will have some more developer-friendly details
      throw new AttestationError(error as Error);
    }

  }
}

export {AttestationManager, Attestation, AttestationPayload, AttestationError};