import { ConsumeOptions, V4, errors } from 'paseto';
import NodeCache from 'node-cache';

/**
 * See https://docs.authenticvision.com/sdk/pdf/sip-v4-paseto.pdf for details
 */
type AttestationPayload = {
  /**
   * The SecureLabel-ID (SLID), uniquely identifying the label
   */
  slid: string;
  /**
   * The subject, i.e. install_id of the scan. Can be used as an (unreliable) way of user identification
   */
  sub: string | undefined;
  /**
   * Alphanumeric string to uniquely identify this scan in AV’s audit database.
   * There exists at most one attestation token per jti
   */
  jti: string;
  /**
   * Authentication result. Recommended to not use directly but use Attestation's isAuthenticated() and isFraud().
   */
  result: string | undefined;
  /**
   * External references. An array elements (usually stringified json-objects) providing additional data through
   * AV's infrastructure. This data is trustworthy.
   */
  extrefs: Array<object>;

  // TODO location, gtin, exp, iat, aud, _v etc
}

/**
 * Parameters to configure decoding options
 */
interface DecodeParameters {
  /**
   * If true, token is decoded but not redeemed. 
   * This does not undo previous redemptions, so if a token is already redeemed, it will no longer be decode-able
   */
  noRedeem?: boolean;
}

class AttestationError extends Error {
  constructor(
    private originalError: Error) {
    super(originalError.message);
    // Set the prototype explicitly.
    Object.setPrototypeOf(this, AttestationError.prototype);
  }

  // TODO explicit indicator functions for whether token expired, redeemed etc.
}

/**
 * Decoded Attestation
 */
class Attestation {
  constructor(
    private readonly payload: AttestationPayload,
    private readonly token: string
  ) {

  }

  /**
   * 
   * @returns The SLID in Base36 format
   */
  public getSlid(): string | undefined {
    return this.payload?.slid;
  }

  /**
   * Indicates whether the label with SLID has been confirmed authentic 
   * @returns true if authenticated.
   */
  public isAuthenticated(): boolean {
    return this.payload?.result == "AUTHENTIC";
  }

  /**
   * Indicates whether the scan from a label with SLID has been flagged as fraud attempt
   * @returns true if fraud is indicated.
   */
  public isFraud(): boolean {
    return this.payload?.result== "COUNTERFEIT"
  }

  /**
   * Computes and returns hash of the present token.
   * @returns Stringified hash, can be used to uniquely identify an attestation token
   */
  public getHash(): string {
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256').update(this.token).digest('hex');
    return hash;
  }

  /**
   * Returns the payload raw as decoded
   * @returns Payload as decoded
   */
  public getPayload(): AttestationPayload {
    return this.payload;

  }
}

/**
 * A simple attestation manager allowing to decode and redeem attestation tokens. 
 * Automatically redeeming a token when decoding is default behavior, so each attestation token can be decoded only once.
 * This prevents and minimizes the risk of replay- and phising attacks.
 */
class AttestationManager  {
  private keyCache: NodeCache  = new NodeCache();
  private keyServerUrl: string = "https://sip-keys.authenticvision.com/v4";
  // stores token.jti together with the redeem date
  private redeemedCache: NodeCache = new NodeCache();
  private defaultPasetoOptions: ConsumeOptions<true> = {
    clockTolerance: "5s",
    complete: true
  };

  constructor() {

  }

  /**
   * Adds a dedicated key for Attestation token decoding.
   * Typically not required, as keys are resolved internally via key-servers.
   * 
   * @param keyId Key-ID as string in format 'k4.pid.*'
   * @param publicKey Public Key as string in format 'k4.public.*'
   */
  public addKey(keyId: string, publicKey: string) {
    this.keyCache.set(keyId, publicKey);
  }

  private async resolvePasetoKey(keyId:string): Promise<string> {
    const cachedKey = this.keyCache.get<string>(keyId);
    if (cachedKey) {
       return cachedKey;
    }

    const response = await fetch(`${this.keyServerUrl}/${keyId}`);
    const key = await response.text();
    this.keyCache.set(keyId, key);
    return key;
  }

  private tokenRedemption(attestation: Attestation, params?: DecodeParameters) {
    const hash = attestation.getPayload().jti;    
    const redeemDate = this.redeemedCache.get<Date>(hash);
   
    if(redeemDate) {
      const err = new Error(`Attestation-Token ${hash} already redeemed on ${redeemDate.toString()}`);
      throw err;
    }

    if(!params?.noRedeem) {        
      this.redeemedCache.set(hash, new Date());
    }
  }

/**
 * Activates development mode, do not use in production.
 * Uses a key-server supporting developer-tokens generated at https://api.metaanchor.io
 */
  public activateDevelopmentMode(): void {
    this.keyServerUrl = "https://api.metaanchor.io/api/v1/attestation/keys/v4"
  }

  /**
   * Decodes and redeems `token`
   * Each token can be decoded once. Use external mechanisms such as sessions if the token's content are required multiple times.
   * 
   * Default behavior can be changed using `params`
   * 
   * @throws {AttestationError} When token is either expired, no key available, already redeemed etc.
   * 
   * @param token The token to be decoded. String in format 'v4.public.*'
   * @param params Optional Parameters, see docs
   * @returns Attestation, when successfully decoded. Throws otherwise
   */
  public async decode(token: string, params?: DecodeParameters, pasetoOptions?: ConsumeOptions<true> ): Promise<Attestation> {
    try {
      const parsedToken = JSON.parse(Buffer.from(token.split('.')[3], 'base64').toString('utf-8'));

      // Key retrieval
 
      const pubkid = parsedToken.kid;
      const pubKey = await this.resolvePasetoKey(pubkid); // FIXME error handling!      
      
      // For demo-purposes, decode it even if expired
      //const rawPayload = (await V4.verify(token, pubKey!, { ignoreExp: true, complete: true }))?.payload as AttestationTokenPayload;
      
      // Any provided pasetoOptions will overwrite the default options
      const mergedOptions: ConsumeOptions<true> = Object.assign({}, this.defaultPasetoOptions, pasetoOptions);

      const validatedPayload = await V4.verify(token, pubKey!, mergedOptions);
      const attestation = new Attestation(validatedPayload?.payload as AttestationPayload, token); 
      
      // Throws if key already redeemed
      this.tokenRedemption(attestation, params);
      return attestation;
    } catch (error) {
      // Package into a typed error, which will have some more developer-friendly details
      throw new AttestationError(error as Error);
    }
  }

  /**
   * Clears key- and redemption cache. Note clearing the redemption cache may
   * pose a security issue as it opens vulnerabilities for replay attacks.
   */
  public clearCaches(): void {
    this.keyCache.flushAll();
    this.redeemedCache.flushAll();
  } 
}

const attestationDecoder = new AttestationManager();

// Do not export the Attestation Manager class on purpose to avoid mixups...
export {attestationDecoder, AttestationManager, Attestation, AttestationPayload, AttestationError};