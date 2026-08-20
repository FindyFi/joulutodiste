import  express from "express";
import { agent } from './agent.js'

const VALIDITY_MS = 365 * 24 * 60 * 60 * 1000 // credential validity time in milliseconds

const config = {
  "server_port": process.env.JOULU_SERVER_PORT || 9627
}

const app = express();
app.use(express.json())
app.use(express.static('public'))

app.post('/issue', async (req, res) => {
  if (!req.body.Etunimi || !req.body.Sukunimi) {
    res.status(400).json({ error: 'Missing required claim values' })
    return false
  }
  const credentialParams = {
    credentialSchemaId: agent.schemas.credential.id,
    issuer: agent.issuer.id,
    issuerKey: agent.issuer.keyId,
    protocol: req.body.protocol || 'OPENID4VCI_FINAL1',
    claimValues: []
  }
  agent.schemas.credential.claims.forEach(claim => {
    let value = req.body[claim.key]
    if (claim.key === 'Kiltti') {
      value = value === 'true' ? "true" : "false"
    }
    credentialParams.claimValues.push({
      claimId: claim.id,
      value: value,
      path: `${claim.key}`
    })
  })
  const offer = await agent.issueCredential(credentialParams)
  if (offer) {
    res.json(offer)
    return true
  }
  res.status(500).json({ error: 'Failed to create credential offer' })
})

app.post('/verify', async (req, res) => {
  const proofParams = {
    proofSchemaId: agent.schemas.proof.id,
    verifier: agent.verifier.id,
    protocol: req.body.protocol || 'OPENID4VP_FINAL1',
    transport: ['HTTP'],
    clientIdScheme: 'did'
  }
  const request = await agent.requestCredential(proofParams)
  if (request) {
    res.json(request)
    return true
  }
  res.status(500).json({ error: 'Failed to create credential request' })
})

app.get('/status/:id', async (req, res) => {
  const status = await agent.getStatus(req.params.id)
  if (status) {
    res.json(status)
    return true
  }
  res.status(500).json({ error: `Failed to check status for ${req.params.id}` })
})

app.listen(config.server_port, () => {
  console.log(`Server is running on port ${config.server_port}`)
})
