import { AttestationError, AttestationManager } from '../src';
import { describe, test, expect } from "@jest/globals"

const KEY_ID = "k4.pid.2uab3h18sgaYX1PKFW3OIMvGIfAMnuwWBJ6TuCbuwQii";
const KEY_PUBKEY = "k4.public.f2AxH__c3AQy_abwIYAZvwzLYrLPAUNH5o6cFzPj1_0";


describe('Decoding tests', () => {  
  // This token will expire 2030-01-01T00:00:00Z. Expect the test to fail then!
  const testToken: string = "v4.public.eyJhdWQiOiJleGFtcGxlLmNvbSIsImV4cCI6IjIwMzAtMDEtMDFUMDA6MDA6MDBaIiwiaWF0IjoiMjAyMy0wNC0yMFQxNjo1NDowMVoiLCJqdGkiOiJmOGIxZDdmNzNiNzEzYWY0M2FkNTllMzNiN2MwMmRmNSIsInJlc3VsdCI6IkFVVEhFTlRJQyIsInNsaWQiOiJaNDVKQkpSNlM5IiwibG9jYXRpb24iOnsibGF0Ijo0Ny43OTQ2LCJsb24iOjEyLjk4NjR9LCJleHRyZWZzIjpbImZvbyIseyJiYXIiOiJiYXoifSwxMjNdffeoKRK7wfueWl9ti4h9JTYM2ZOXOPgHMOq-6eRxFEKFUYz1LLcNxUp9JtHHY-FD5pHxP9OQ9nOg_izxMwK3GgU.eyJraWQiOiAiazQucGlkLjJ1YWIzaDE4c2dhWVgxUEtGVzNPSU12R0lmQU1udXdXQko2VHVDYnV3UWlpIn0";
  const testTokenExpired: string = "v4.public.eyJhdWQiOiAiZXhhbXBsZS5jb20iLCAianRpIjogImY4YjFkN2Y3M2I3MTNhZjQzYWQ1OWUzM2I3YzAyZGY1IiwgInJlc3VsdCI6ICJBVVRIRU5USUMiLCAic2xpZCI6ICJaNDVKQkpSNlM5IiwgImxvY2F0aW9uIjogeyJsYXQiOiA0Ny43OTQ2LCAibG9uIjogMTIuOTg2NH0sICJleHRyZWZzIjogWyJmb28iLCB7ImJhciI6ICJiYXoifSwgMTIzXSwgImlhdCI6ICIyMDI0LTA0LTE4VDA2OjU1OjEyLjE5MzM5M1oiLCAiZXhwIjogIjIwMjQtMDQtMThUMDY6NTU6MTMuMTkzMzkzWiJ9enaNZ821y2c-2efnOqzzXdHRFVwQ5nlmTy8ES53SD-3-ahZbFeh9s1KSNLkZEyfdVi3qgydCWQ2enxYwkr9QCw.eyJraWQiOiAiazQucGlkLjJ1YWIzaDE4c2dhWVgxUEtGVzNPSU12R0lmQU1udXdXQko2VHVDYnV3UWlpIn0"
  
  let mgr: AttestationManager;

  beforeEach(() => {
    mgr = new AttestationManager();
    // From https://docs.authenticvision.com/sdk/pdf/sip-v4-paseto.pdf
    mgr.addKey(KEY_ID, KEY_PUBKEY)
  });

  it('Decodes token', async () => {
    const attestation = await mgr.decode(testToken);
    expect(attestation?.getSlid()).toEqual("Z45JBJR6S9");
  });

  it('Does not decode expired token', async () => {
    await expect(mgr.decode(testTokenExpired)).rejects.toThrow(AttestationError);
    // TODO better tests testing the AttestationError functionalty (not implemented yet)
    // Should have .errorCode() with UKNOWN_KEY, EXPIRED, ALREADY_REDEEMED, DECODE_FAILURE, KEYSERVER_UNREACHABLE etc etc.
  });

  it('Decodes expired token, when expiry is ignroed', async () => {
    const attestation = await mgr.decode(testTokenExpired, {ignoreExpiry:true});
    expect(attestation?.getSlid()).toEqual("Z45JBJR6S9");
  });
});

describe('Basic usage', () => {
  // This token will expire 2030-01-01T00:00:00Z. Expect the test to fail then!
  const testTokenAuthentic: string = "v4.public.eyJhdWQiOiJleGFtcGxlLmNvbSIsImV4cCI6IjIwMzAtMDEtMDFUMDA6MDA6MDBaIiwiaWF0IjoiMjAyMy0wNC0yMFQxNjo1NDowMVoiLCJqdGkiOiJmOGIxZDdmNzNiNzEzYWY0M2FkNTllMzNiN2MwMmRmNSIsInJlc3VsdCI6IkFVVEhFTlRJQyIsInNsaWQiOiJaNDVKQkpSNlM5IiwibG9jYXRpb24iOnsibGF0Ijo0Ny43OTQ2LCJsb24iOjEyLjk4NjR9LCJleHRyZWZzIjpbImZvbyIseyJiYXIiOiJiYXoifSwxMjNdffeoKRK7wfueWl9ti4h9JTYM2ZOXOPgHMOq-6eRxFEKFUYz1LLcNxUp9JtHHY-FD5pHxP9OQ9nOg_izxMwK3GgU.eyJraWQiOiAiazQucGlkLjJ1YWIzaDE4c2dhWVgxUEtGVzNPSU12R0lmQU1udXdXQko2VHVDYnV3UWlpIn0";
  const testTokenCounterfeit: string = "v4.public.eyJhdWQiOiAiZXhhbXBsZS5jb20iLCAianRpIjogIjJhZTBmOTIxZWNhZjJiYjNlNjg5ZTBkMDUxYjUwYzhiIiwgInJlc3VsdCI6ICJDT1VOVEVSRkVJVCIsICJzbGlkIjogIlo0NUpCSlI2UzkiLCAibG9jYXRpb24iOiB7ImxhdCI6IDQ3Ljc5NDYsICJsb24iOiAxMi45ODY0fSwgImV4dHJlZnMiOiBbImZvbyIsIHsiYmFyIjogImJheiJ9LCAxMjNdLCAiaWF0IjogIjIwMjQtMDQtMThUMDc6MzQ6NDIuMzM4OTcwWiIsICJleHAiOiAiMjAyNC0wOS0xN1QwOTozNDo0Mi4zMzg5NzBaIn2KSrNg7Dhf_6F7t028ZITRD6BrIO-J1VO3zLEPkP4Mx9g4QOEOf5WpPK-rNiglkxqmWwcM7ah4wrm7CGkca9UM.eyJraWQiOiAiazQucGlkLjJ1YWIzaDE4c2dhWVgxUEtGVzNPSU12R0lmQU1udXdXQko2VHVDYnV3UWlpIn0"
  const testTokenIdentified: string = "v4.public.eyJhdWQiOiAiZXhhbXBsZS5jb20iLCAianRpIjogImY4YjFkN2Y3M2I3MTNhZjQzYWQ1OWUzM2I3YzAyZGY1IiwgInN1YiI6ICIzMWJlZDcyNTFiODA4YjFlYjZlMjJmNDE4MGJhZTc4MCIsICJzbGlkIjogIlo0NUpCSlI2UzkiLCAicmVzdWx0IjogIklERU5USUZJRUQiLCAiaWF0IjogIjIwMjQtMDQtMThUMTI6MDg6NDEuNjAyMDg1WiIsICJleHAiOiAiMjAyNC0wNC0xOFQxMjoxMzo0MS42MDIwODVaIn0rVkBx0khwk9naaNy4m7HeVI7y21ZV9S0t9_RswpJYOaMmSO9iGfp6mM_I85d4nkgJy-htzwz-33LEFVphhF0M.eyJraWQiOiAiazQucGlkLjJ1YWIzaDE4c2dhWVgxUEtGVzNPSU12R0lmQU1udXdXQko2VHVDYnV3UWlpIn0";
  let mgr: AttestationManager;

  beforeEach(() => {
    mgr = new AttestationManager();
    mgr.addKey(KEY_ID, KEY_PUBKEY)
  });

  it('Check Authentic token', async () => {
    const attestation = await mgr.decode(testTokenAuthentic);
    expect(attestation?.isAuthenticated()).toEqual(true);
    expect(attestation?.isFraud()).toEqual(false);
    expect(attestation?.getSlid()).toEqual("Z45JBJR6S9");
  });

  it('Check Fraud token test', async () => {
    const attestation = await mgr.decode(testTokenCounterfeit);
    expect(attestation?.isAuthenticated()).toEqual(false);
    expect(attestation?.isFraud()).toEqual(true);
    expect(attestation?.getSlid()).toEqual("Z45JBJR6S9");
  });  
});