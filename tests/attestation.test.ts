import { AttestationError, attestationDecoder} from '../src';
import { describe, test, expect } from "@jest/globals"

const KEY_ID = "k4.pid.2uab3h18sgaYX1PKFW3OIMvGIfAMnuwWBJ6TuCbuwQii";
const KEY_PUBKEY = "k4.public.f2AxH__c3AQy_abwIYAZvwzLYrLPAUNH5o6cFzPj1_0";


describe('Attestation utility tests', () => {  
  // This token will expire 2030-01-01T00:00:00Z. Expect the test to fail then!
  const testToken: string = "v4.public.eyJhdWQiOiJleGFtcGxlLmNvbSIsImV4cCI6IjIwMzAtMDEtMDFUMDA6MDA6MDBaIiwiaWF0IjoiMjAyMy0wNC0yMFQxNjo1NDowMVoiLCJqdGkiOiJmOGIxZDdmNzNiNzEzYWY0M2FkNTllMzNiN2MwMmRmNSIsInJlc3VsdCI6IkFVVEhFTlRJQyIsInNsaWQiOiJaNDVKQkpSNlM5IiwibG9jYXRpb24iOnsibGF0Ijo0Ny43OTQ2LCJsb24iOjEyLjk4NjR9LCJleHRyZWZzIjpbImZvbyIseyJiYXIiOiJiYXoifSwxMjNdffeoKRK7wfueWl9ti4h9JTYM2ZOXOPgHMOq-6eRxFEKFUYz1LLcNxUp9JtHHY-FD5pHxP9OQ9nOg_izxMwK3GgU.eyJraWQiOiAiazQucGlkLjJ1YWIzaDE4c2dhWVgxUEtGVzNPSU12R0lmQU1udXdXQko2VHVDYnV3UWlpIn0";

  beforeEach(() => {
    // From https://docs.authenticvision.com/sdk/pdf/sip-v4-paseto.pdf
    attestationDecoder.clearCaches();
    attestationDecoder.addKey(KEY_ID, KEY_PUBKEY)
  });

  it('SecondsToExpiry relative to defined time', async () => {
    const attestation = await attestationDecoder.decode(testToken);
    const SecondsBeforeExpiry = "2029-12-31T23:59:30Z"; // 30 sec left
    // TODO maybe add tests that define the tolerance, i.e. to how many MS is this accurate etc
    expect(attestation?.secondsToExpiry(SecondsBeforeExpiry)).toEqual(30.0);
  });

  it('SecondsToExpiry relative to defined time', async () => {
    const attestation = await attestationDecoder.decode(testToken);
    const timeNow = new Date().getTime();
    const expTime = new Date(attestation!.getPayload().exp).getTime()

    // time left
    // Note this test will start failing starting 2030-01-01, because the time left becomes negative!
    const timeInSecondsLeft = (expTime - timeNow) / 1000.0;
    const eps = 0.5; // 0.5 sec grace for test runtime
    expect(attestation?.secondsToExpiry()).toBeGreaterThanOrEqual(timeInSecondsLeft);
    expect(attestation?.secondsToExpiry()).toBeLessThanOrEqual(timeInSecondsLeft + eps);
  });

  it('SecondsToExpiry negative if expired', async () => {
    const attestation = await attestationDecoder.decode(testToken);
    const SecondsBeforeExpiry = "2030-01-01T00:01:00Z"; // expired for 60sec
    // TODO maybe add tests that define the tolerance, i.e. to how many MS is this accurate etc
    expect(attestation?.secondsToExpiry(SecondsBeforeExpiry)).toEqual(-60.0);
  });


});