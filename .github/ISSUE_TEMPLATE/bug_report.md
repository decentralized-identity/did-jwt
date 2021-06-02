---
name: Bug report
about: Create a report to help us improve

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Using this piece of code 
```typescript
const didJWT = require('did-jwt')
const signer = didJWT.ES256KSigner(myKey)

let token = await didJWT.createJWT(/*...*/)
///...
```
2. in this context...
3. I see this error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Samples**
The ideal bug report links to a sample project that reproduces the error,
or includes a failing test that will pass once the error is fixed. 

**Desktop (please complete the following information):**
 - OS: [e.g. iOS]
 - Browser/Node [e.g. chrome, safari, node 14.17.0]
 - Version [e.g. 22]

**Smartphone (please complete the following information):**
 - Device: [e.g. iPhone6]
 - OS: [e.g. iOS8.1]
 - Browser [e.g. stock browser, safari]
 - Version [e.g. 22]

**Additional context**
Add any other context about the problem here.
