{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE BangPatterns      #-}
module Main where

import Prelude hiding (length)

import Network.DNS.Types
import Network.Simple.TCP.TLS
import Network.TLS
import Network.TLS.Extra
import Text.RawString.QQ
import Control.Exception
import Control.Concurrent

import Control.Monad       (join, void)
import Control.Monad.Fix   (fix)
import Control.Monad.Extra (whenJust)
import Data.ByteString     (ByteString, length)
import Data.ByteString.Builder         (toLazyByteString, word16BE, byteString)
import Data.ByteString.Lazy (toStrict)
import Data.Monoid         ((<>))
import System.Timeout      (timeout)
import Network.DNS.Decode  (decodeMany)
import Network.DNS.Encode  (encode)

main :: IO ()
main =
  serve sSettings "*" "1853" $ \ (ctx, _sa) -> 
    (`fix` "") $ \ loop !leftover -> handle onSomeException $ do
      mBody <- timeout 5000000 $ recv ctx
      whenJust (join mBody) $ \body -> do
        let (dnsMessages, leftover') = either throw id 
                                     $ decodeMany $ leftover <> body
        mapM_ (handleRequest ctx) dnsMessages
        loop leftover'
  where
    sSettings = applySecurityParams $ makeServerSettings cred Nothing
    applySecurityParams = updateServerParams $ \ sp ->
      let sup  = serverSupported sp
          sup' = sup { supportedVersions                     = [TLS12,TLS11]
                     , supportedCiphers                      = ciphersuite_strong
                     , supportedCompressions                 = [nullCompression]
                     , supportedSecureRenegotiation          = True
                     , supportedClientInitiatedRenegotiation = False
                     , supportedSession                      = True
                     , supportedFallbackScsv                 = False
                     , supportedEmptyPacket                  = True
                     }
      in sp {serverSupported = sup'}
    cred = either error id
         $ credentialLoadX509FromMemory cert key

onSomeException :: SomeException -> IO ()
onSomeException e = putStrLn $ "Catch exception: " <> show e

handleRequest :: Context -> DNSMessage -> IO ()
handleRequest ctx (DNSMessage hdr@(DNSHeader _ hdrFlags@(DNSFlags QR_Query OP_STD _ _ _ _ _ _)) questions _ _ _) =
  void . forkIO $
    do
      let respHdr = hdr { flags = hdrFlags { qOrR = QR_Response,
                                             recAvailable = True,
                                             rcode = ServFail } }
          respMsg = encode $ DNSMessage respHdr questions [] [] []
      send ctx $ addFrame respMsg

handleRequest _ _ = return ()

addFrame :: ByteString -> ByteString
addFrame b = toStrict . toLazyByteString
           $ word16BE (fromIntegral $ length b) <> byteString b

cert :: ByteString
cert = [r|
-----BEGIN CERTIFICATE-----
MIIChjCCAe+gAwIBAgIJAKo3PTdhQuzjMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAkRFMRAwDgYDVQQIDAdIYW1idXJnMRAwDgYDVQQHDAdIYW1idXJnMRIwEAYD
VQQKDAlTZWN1Y2xvdWQxFTATBgNVBAMMDFl1cmEgU2hlbGlhaDAeFw0xODA3MDUw
OTI2MzdaFw0xOTA3MDUwOTI2MzdaMFwxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdI
YW1idXJnMRAwDgYDVQQHDAdIYW1idXJnMRIwEAYDVQQKDAlTZWN1Y2xvdWQxFTAT
BgNVBAMMDFl1cmEgU2hlbGlhaDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
lIeGQDbR1VntAC9NUDucXKA2PVp8RYhlZnkl33jmLRSLdeL+ICN1ni9XkBfW6woD
6znzWocgYM0TGFGv7wmwJliZmx+dL2COXsIszumYbnh30Wagp3yRQ6mSwvWNdw9f
yhktPOfY1Ca2JIXD9P9WVTuc2p7kjMVPARoqKtu32AECAwEAAaNQME4wHQYDVR0O
BBYEFLI5tLhHieFIzaBmlugo9t/rtUOXMB8GA1UdIwQYMBaAFLI5tLhHieFIzaBm
lugo9t/rtUOXMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAOCcitTyU
12srcTBDpRrbUkR5NgsC7tDqsU6MFMlHrlRhJ+vm5fScWypDimqtnJu0Ox9GAXld
psEUdVW27Og/4PBe9D7U9RTMl9igOmEb+kmdQD9VtIABP+U2VraCQkLyo5CXlqWF
lZ37UIm+tQxkMT6kcGa/B6PfG+aI7y/tlC0=
-----END CERTIFICATE-----
|]

key :: ByteString
key = [r|
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCUh4ZANtHVWe0AL01QO5xcoDY9WnxFiGVmeSXfeOYtFIt14v4g
I3WeL1eQF9brCgPrOfNahyBgzRMYUa/vCbAmWJmbH50vYI5ewizO6ZhueHfRZqCn
fJFDqZLC9Y13D1/KGS0859jUJrYkhcP0/1ZVO5zanuSMxU8BGioq27fYAQIDAQAB
AoGAdphz+MgM6gdAtxoN6JeAdXEzfe/HNJoBJT5soDBf0fUKmhmigjTuEF2K1DJE
2C2KDYObLVih4Mk+iveGvB4HOI+suhV5xk2K0kcyek7keUUYh1zhDY1nd+PiZh31
ze+i7gmhAwZd5K0sAY2MpQHFiwoaS5QDLaXE3aJD4T438AECQQDF9JWP03pNkhiQ
dEuQg4FkKDyaJ/TFBfToAmF+0m/Vwjc1hR2LXv8T5LxTeV1tLVgukTiEfT6qoggY
jsE09FzBAkEAwBTNlcHK/oVlfTKZNYWeyvMVZqFM9qNHEaCI1XeKt+RGwBr8hIXz
LKek8HKCU8moFNUCYi/XADOuJXa+ZbALQQJBAL2f9OEoqKDEEWnXLUeK4ZjK/nqB
SfSuJxNUrIYrGVw/xlkrYcjPQDOTSmAAA2IBLNa239fyjeQwgObdYPDUIEECQGtg
9dD7ZlzE/Ahyad3W1f+Exvj5wUm723YKNZSIYH8O2VJ5g6MeMuRKz9UvXpYyjIkg
z1VOgzX0riz5ZdT5BkECQQCOqePeUe7uqb7DQn2Kwc9urOG/3qtR4JBkcLUKMu3r
RXcNwpCGNBau9QUbOT+hcZt4FWfFWjav13FQvIeVbnuA
-----END RSA PRIVATE KEY-----
|]
