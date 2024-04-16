# attestation-js
Authentic Vision / Meta Anchor attestation tools


## Getting started

### In Production
```
import { AttestationManager } from '@authenticvision/attestation';

// Typically, a GET-Parameter 'av_sip' is carrying the attestation token
// We assume to have a NodeJS-Request object 'req' available.
const token = req.query?.av_sip

if(token) {
    const mgr = new AttestationManager();
    try {
        const attestation = await mgr.decode(token);
        const slid = attestation.getSlid(); // An attestation *always* has a SecureLabel-Identifier (SLID)
        
        if(attestation.isAuthenticated()) {
            console.log(`Authenticated attestation received. It's safe to unlock value for slid=${slid}`)
            } else {        
            if(attestation.isFraud()) {
                console.log(`FRAUD detected for ${slid} - handle it!`);
            } else {
                // Its not fraud, and the label can be identified. Some "ungated" information could be displayed
                console.log(`A SLID is known, but not authenticated. You may display public information for slid=${slid}`)
            }        
        }
    } catch(e) {
        // Key not found, token expired, already redeemed before, .... 
        console.error(e); 
    }
}
```

### For local development:
- Request an API-Key at XXXX
- Use https://api.metaanchor.io/api/v1/attestation/dev/generate to generate development-attestations
- Set `mgr.setDevelopment(true)` to enable the development-keyserver. Make sure to not use this line in production!

Complete example:

```
import { AttestationManager } from '@authenticvision/attestation';

// Typically, a GET-Parameter 'av_sip' is carrying the attestation token
// We assume to have a NodeJS-Request object 'req' available.
const token = "v4.public.eyJhdWQiOiJleGFtcGxlLmNvbSIsImV4cCI6IjIwMzAtMDEtMDFUMDA6MDA6MDBaIiwiaWF0IjoiMjAyMy0wNC0yMFQxNjo1NDowMVoiLCJqdGkiOiJmOGIxZDdmNzNiNzEzYWY0M2FkNTllMzNiN2MwMmRmNSIsInJlc3VsdCI6IkFVVEhFTlRJQyIsInNsaWQiOiJaNDVKQkpSNlM5IiwibG9jYXRpb24iOnsibGF0Ijo0Ny43OTQ2LCJsb24iOjEyLjk4NjR9LCJleHRyZWZzIjpbImZvbyIseyJiYXIiOiJiYXoifSwxMjNdffeoKRK7wfueWl9ti4h9JTYM2ZOXOPgHMOq-6eRxFEKFUYz1LLcNxUp9JtHHY-FD5pHxP9OQ9nOg_izxMwK3GgU.eyJraWQiOiAiazQucGlkLjJ1YWIzaDE4c2dhWVgxUEtGVzNPSU12R0lmQU1udXdXQko2VHVDYnV3UWlpIn0"

if(token) {
    const mgr = new AttestationManager();
    mgr.activateDevelopmentMode() // FIXME DO NOT SHIP THIS LINE TO PRODUCTION
    
    try {
        const attestation = await mgr.decode(token);
        const slid = attestation.getSlid(); // An attestation *always* has a SecureLabel-Identifier (SLID)
        
        if(attestation.isAuthenticated()) {
            console.log(`Authenticated attestation received. It's safe to unlock value for slid=${slid}`)
            } else {        
            if(attestation.isFraud()) {
                console.log(`FRAUD detected for ${slid} - handle it!`);
            } else {
                // Its not fraud, and the label can be identified. Some "ungated" information could be displayed
                console.log(`A SLID is known, but not authenticated. You may display public information for slid=${slid}`)
            }        
        }
    } catch(e) {
        // Key not found, token expired, already redeemed before, .... 
        console.error(e); 
    }
}
```