
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJDswaydMNYuhSMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi0xNWYyM3pvYS51cy5hdXRoMC5jb20wHhcNMjIwOTA3MTEyMjE3WhcN
MzYwNTE2MTEyMjE3WjAkMSIwIAYDVQQDExlkZXYtMTVmMjN6b2EudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuNnRULEULhYjFpR5
2VhTvdFcjvYE8nKy3pCBH4Wev+SuHKxjEM4ybob3tkfPez1UJn3KOrfdEsnYv5h9
rui1Pp14LnD6Fn6AJI4hNip3jKrw6VqwpDzf8AZk6Oaz6ftMfZy6yj3XBSi09c8c
Tt2tAHVC4gxwWyo7U/VuW7kaFp0ukdVBAyanOKmOnCsBhSkwgmvQiEX3ccPPgXMk
KrqkzhcLOiQGWraR0rjeTUQlEP6HHS38djjySM6uL1CeK9N+z40aQhYoxEX7dGVt
dKy9y+Z3TE2fno26EdXvYJJk2fq7xggk+nuRk7s/iI8z3USxzpHTDOVWcGRRrD+h
Nnp0+wIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTrx+pvBjO1
IP4gzpAVVeZHzanO+jAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AIEJLfJVJbraE1AQU62Eq/Tj9bOWrGzcTyn5S4oZLNzb3VRNNEZneiJ1gAuSM3SD
TMyKwbbuN7c1RvRVuiEsRqLRYZ2H9XhGQ/BdocUj43bigu92QYNIvaggwGosafox
0UYxuXLrxf/SRjYTSrUimcH6DOX4JuxVSHQgoShH5mcoXj9hp2hN2k1tr/WwZs+K
mtfoXGAF5B94XlBKqJigs8KVw3mk14AwbhPBJVwmhGtwAgROeVlFqW4FzWFyVG3w
wbNrxh29jLr2sIKYiSQr7Bhp4Q2zdjvqu7pYRGW8f7N9J4SqYHqOz657mRVdb07B
Ix/CLFGo2khz72sa3roSwYA=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
