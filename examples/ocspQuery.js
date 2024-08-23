const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});

let uri = 'http://ocsp.cyopki.com/'

let hash = 'sha256'

let cacert = `
-----BEGIN CERTIFICATE-----
MIIFsjCCBJqgAwIBAgIUBrpEbRLhJA6a0G9mer8Ccw4Xhz0wDQYJKoZIhvcNAQEL
BQAwVTEeMBwGA1UEAwwVUEtJYWFTLmlvIERldiBSb290IENBMQswCQYDVQQGEwJV
UzESMBAGA1UECAwJTG91aXNpYW5hMRIwEAYDVQQKDAlQS0lhYVMuaW8wHhcNMjIw
NTIyMTQ0NzQ1WhcNMzIwNTE5MTQ1MjQ1WjA1MQswCQYDVQQGEwJVUzEmMCQGA1UE
AwwdUEtJYWFTLmlvIERldiBJbnRlcm1lZGlhdGUgQ0EwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDAa6EmnkRDddS9QQ+zO0gzMntkbwNN2jBGJhci3Ct8
rikNxylWONscYcdyzbHd5T2wixHtd5x0qC4GzGZIQjahIFRDBh4qni4Hxu6QlP0V
4xzn1NjLkzy++QZc9Ygc6TucOJj4vAH3jYnKxh6VMYsDs6QD+WwqCq+UeqQxJ5mW
MUzbEv5xST1M8VwJiiOGLReCaeHzWw48a6Ja5kvRK/FG1sbctYL39yp5dnafMZpI
mKoPcddSZvagYCmnZjnY2I1tMUW9VilFZhXdlL96pwdi6A00cF3Rrk3kG9PO49dr
Q2voAp7fE0aC1fYLX2bVjyQ5+thwpxnnzipMKxioNygvAgMBAAGjggKYMIIClDAd
BgNVHQ4EFgQUxRquDbZXRCTioSJ2IByOQ7L15ocwHwYDVR0jBBgwFoAUplC0Nb19
KsQJBmyzuUm6UV3AsI4wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHoGCCsGAQUFBwEBBG4w
bDAiBggrBgEFBQcwAYYWaHR0cDovL29jc3AuY3lvcGtpLmNvbTBGBggrBgEFBQcw
AoY6aHR0cDovL2NlcnRzLmN5b3BraS5jb20vbjhRSGdBSERxVS9QS0lhYVNpb0Rl
dlJvb3RDQWNhLmNydDBHBgNVHR8EQDA+MDygOqA4hjZodHRwOi8vY3JsLmN5b3Br
aS5jb20vbjhRSGdBSERxVS9QS0lhYVNpb0RldlJvb3RDQS5jcmwwQgYDVR0gBDsw
OTA3BgRVHSAAMC8wLQYIKwYBBQUHAgEWIWh0dHBzOi8vY3lvcGtpLmNvbS9uOFFI
Z0FIRHFVL0NQUzCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB3ALDMg+Wl+X1rr3wJ
zChJBIcqx+iLEyxjULfG/SbhbGx3AAABgOxBm54AAAQDAEgwRgIhAMfLcxDjlS7a
bTwDuV86VikMwUdbjuc4sQPyfOBewXB7AiEAqg3SH1JAC4ZovVWXoeYD8QsePIzY
HFs7eqxey1DZR48AdQDDvwOn4cqIQcYHuuP/QnD8pexFsYbrvk4s8/x3hjD19gAA
AYDsQZx4AAAEAwBGMEQCIDVpyyW7fQYMRPdAU6SKYquGiaPnjtIhX5WmxbNe1/Vc
AiAq9xdTx/L8xmC3KNWMMfF84IPDM3JijkXecJ+/cbT4ADANBgkqhkiG9w0BAQsF
AAOCAQEArz0C3OCFz7qYxsfcx7AUi67pGa2te4UTf6vwj1d0yusgkB4Un2bE+HRG
tZ48cXxnf1RvRNLB9CFHrR+LIn7LjXXPlxWsSa4HjW0jjcp8TRkbTqocCIUAiYJF
pk20/BF/Mn1CvfAzQYIdH2p74dDRg5fQngVyvl/jkABox/PUmPCZP4jXHIkK4uQu
v4Omi21gJGQLM4/zZTdxP3ZeXGnvzRz5GDZg4XEdYYoUvxm+6hVd0pfdrnwGViS3
4ZGyoFetBjgEZ1FbqAdelrSAgszDBoHYiUCKG8OzKblAgIswgoifysJ/tnxkPNo2
3R9JNYQs2NAQG9JVKYvo2XK3tzqvRQ==
-----END CERTIFICATE-----
`

let cert = `
-----BEGIN CERTIFICATE-----
MIIGRjCCBS6gAwIBAgIUVlyRxBe2amMyEeNnbigCj8VpNQ4wDQYJKoZIhvcNAQEL
BQAwNTELMAkGA1UEBhMCVVMxJjAkBgNVBAMMHVBLSWFhUy5pbyBEZXYgSW50ZXJt
ZWRpYXRlIENBMB4XDTI0MDgyMDExNDA0NVoXDTI0MDgzMDExNDU0NVowbDELMAkG
A1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMREwDwYDVQQHDAhOZXcgWW9yazEc
MBoGA1UECgwTWWFob28gSG9sZGluZ3MgSW5jLjEZMBcGA1UEAwwQa2VybmVsbWFu
aWFjLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmlhn/SNIf5
IB/tYL6a4QMiCf8+yVLO9QaUJClYmA4DnukjHlXlOntm5FZKSMJvuBKvRZyEuOKk
8qsIfPuDa8LBcZ8+I3wY0eZ2PIww+JbWI5w9clum+W+jmhTQbqFNMTPJuPbeHibg
TSuSBfymiDUr/zn5bjcn8BSgFIf7CjBw+UXblfq/T7wWYVs5MmnEw+ja/gLqFQDq
nM5T0WqytPT3bNL5kr+bRe4GCatqJWqdyodnm4n1HDR8N0XYHnaN9Tp0SlfzusDK
zWKpTfqQ68Ud/lQ2y2J0rOAc5bl39exQAoPmBhr27jHGzOVBA5G9LrBAvGM+qdZj
hnX8K/omV+sCAwEAAaOCAxUwggMRMB0GA1UdDgQWBBQ15JvyR3xLUQdYt/1r/hbn
RH1t6TAfBgNVHSMEGDAWgBTFGq4NtldEJOKhInYgHI5DsvXmhzAOBgNVHQ8BAf8E
BAMCBaAwKgYDVR0lAQH/BCAwHgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcD
BDAMBgNVHRMBAf8EAjAAMIGCBggrBgEFBQcBAQR2MHQwIgYIKwYBBQUHMAGGFmh0
dHA6Ly9vY3NwLmN5b3BraS5jb20wTgYIKwYBBQUHMAKGQmh0dHA6Ly9jZXJ0cy5j
eW9wa2kuY29tLzRWTmhCZzFFalIvUEtJYWFTaW9EZXZJbnRlcm1lZGlhdGVDQWNh
LmNydDBPBgNVHR8ESDBGMESgQqBAhj5odHRwOi8vY3JsLmN5b3BraS5jb20vNFZO
aEJnMUVqUi9QS0lhYVNpb0RldkludGVybWVkaWF0ZUNBLmNybDBMBgNVHSAERTBD
MDcGBFUdIAAwLzAtBggrBgEFBQcCARYhaHR0cHM6Ly9jeW9wa2kuY29tLzRWTmhC
ZzFFalIvQ1BTMAgGBmeBDAECATCCAQYGCisGAQQB1nkCBAIEgfcEgfQA8gB3ALDM
g+Wl+X1rr3wJzChJBIcqx+iLEyxjULfG/SbhbGx3AAABkW+bdeYAAAQDAEgwRgIh
AL7Z6/S4X3pbY36CogRoG8EwjnST6xWd+sk/69/VD0c/AiEAk3eTDxbXtiUzOuXl
vNzdy+NFIft2VvZgWUnl59FukzQAdwDDvwOn4cqIQcYHuuP/QnD8pexFsYbrvk4s
8/x3hjD19gAAAZFvm3ZGAAAEAwBIMEYCIQCe8xocAWy3Jz73Eaf42PXVq1oIwi/v
VJe2fye/q829ZAIhALg+MxR0k/8SbJF0JpwUf37UdubgGnWzPdALXiOl0XrqMFcG
A1UdEQRQME6CEGtlcm5lbG1hbmlhYy5jb22CD2tlcm5lbG1hbmljLmNvbYIUd3d3
Lmtlcm5lbG1hbmlhYy5jb22CE3d3dy5rZXJuZWxtYW5pYy5jb20wDQYJKoZIhvcN
AQELBQADggEBAI/blGjW0KSGkZmjjyDPu8A4lcZNHqjWmA6Gq9noMka9GdpXyVb9
LlYBzx6q00pc8FuGxwwHPByHjdieIKMU7On9JLAECsU6lDZCI2BJ0xvyXGhCKqKg
w3mVgQFcAa+wzeMqozql6QhhEv9uwK2EuQmdQNLmABSshTrp7/Ed+z0/EAEpCA9T
LsAmkpsiKpGILk98yUoKI4SmkgURgvdg3SzKjzSeddskL+j9VflLPiEPqzEf1H/u
XRe88zdUO3/bObimpyIcYz0LmSQNJVzrOMBhZf+UM/z1/NFCjS+brLS6OAK7jRKb
St8kVAdN//uDlgeebO7rRbbxoYrurOGqdhg=
-----END CERTIFICATE-----
`

openssl.ocsp.query({cert: cert, cacert: cacert,  hash:hash, uri: uri}, function(err, ocsp) {
    if(err) {
        console.log(err);
    } else {
        console.log(ocsp.command);
    }
})